import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/rendering.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
import 'package:p2wlan_flutter_client/app/navigation_model.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/capabilities/platform_capabilities.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/presentation/network_overview.dart';
import 'package:p2wlan_flutter_client/core/rooms/parallel_rooms.dart';
import 'package:p2wlan_flutter_client/core/rooms/room_api.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/dashboard/dashboard_page.dart';
import 'package:p2wlan_flutter_client/features/diagnostics/diagnostics_page.dart';
import 'package:p2wlan_flutter_client/features/nodes/nodes_page.dart';
import 'package:p2wlan_flutter_client/shared/network_overview_presentation.dart';
import 'package:p2wlan_flutter_client/shared/widgets/app_nav_rail.dart';
import 'package:p2wlan_flutter_client/shared/widgets/desktop_sidebar.dart';

const _roomOne = 'room-00000000000000000000000000000001';
const _roomTwo = 'room-00000000000000000000000000000002';
final _token =
    'a.${base64Url.encode(utf8.encode(jsonEncode({'user_id': 'member'})))}.b';

FriendRoom _room(int number) => FriendRoom(
  id: number == 1 ? _roomOne : _roomTwo,
  code: '$number'.padLeft(8, '0'),
  name: 'Room $number',
  cidr: '10.21.$number.0/24',
  ownerId: 'member',
  role: 'owner',
  locked: false,
);

DiagnosticsSnapshot _snapshot(
  String networkId,
  int subnet, {
  bool stale = false,
  bool capturedMismatch = false,
  bool online = true,
}) => DiagnosticsSnapshot.fromJson({
  'network_id': networkId,
  'node_id': 'local',
  'virtual_ip': '10.21.$subnet.2',
  'process_id': 100 + subnet,
  'runtime_incarnation': 1,
  'network_generation': subnet,
  'revision': 8,
  'captured_revision': capturedMismatch ? 7 : 8,
  'peer_snapshot_stale': stale,
  'health': {
    'status': 'healthy',
    'control_connected': true,
    'device_lease_healthy': true,
  },
  'peers': [
    {
      'node_id': 'same-node',
      'device_name': 'Shared laptop',
      'virtual_ip': '10.21.$subnet.3',
      'online': online,
      'state': 'direct',
      'active_path': 'direct',
      'direct': {'latency_ms': 12, 'last_success_age_ms': 0},
    },
  ],
});

class _Runtime implements RoomRuntime {
  _Runtime(this.plan);
  final ParallelRoomPlan plan;
  @override
  Future<bool> exists() async => false;
  @override
  Future<DaemonCommandResult> start() async =>
      const DaemonCommandResult(ok: true, message: '');
  @override
  Future<DaemonCommandResult> stop() async =>
      const DaemonCommandResult(ok: true, message: '');
  @override
  Future<DiagnosticsSnapshot> status() async =>
      _snapshot(plan.room.id, plan.room.id == _roomOne ? 1 : 2);
  @override
  void close() {}
}

class _Store extends StatusStore {
  _Store({required super.settingsStore, required super.parallelRooms})
    : super(diagnosticsApi: DiagnosticsApi(), enableEventPolling: false);
  DiagnosticsSnapshot? primary;
  @override
  DiagnosticsSnapshot? get snapshot => primary;
  @override
  bool get healthReachable => primary != null;
  @override
  bool get daemonReachable => primary != null;
  @override
  Map<String, int> get peerTransferRatesBytesPerSecond => const {
    'same-node': 8192,
  };
}

class _Harness {
  _Harness(this.directory, this.settings, this.store);
  final Directory directory;
  final SettingsStore settings;
  final _Store store;
  void dispose() {
    store.dispose();
    settings.dispose();
    directory.deleteSync(recursive: true);
  }
}

Future<_Harness> _harness({int rooms = 2}) async {
  final directory = await Directory.systemTemp.createTemp(
    'network-overview-test-',
  );
  final settings = SettingsStore(
    settingsFile: File('${directory.path}/settings.json'),
    tokenRepository: InMemorySecureTokenRepository(),
  );
  await settings.load();
  await settings.updateSettings(
    settings.settings.copyWith(
      controlServer: 'https://control.example',
      authToken: _token,
      languageCode: 'en',
      deviceName: 'Work laptop',
    ),
  );
  final manager = ParallelRooms(
    readSettings: () => settings.settings,
    runtimeFactory: _Runtime.new,
    supported: true,
    refreshInterval: Duration.zero,
  );
  final store = _Store(settingsStore: settings, parallelRooms: manager);
  for (var index = 1; index <= rooms; index++) {
    expect((await manager.connect(_room(index))).ok, isTrue);
  }
  return _Harness(directory, settings, store);
}

Widget _app(Widget child, {double textScale = 1}) => AppStringsScope(
  strings: AppStrings.fromCode('en'),
  child: MaterialApp(
    theme: AppTheme.lightTheme,
    home: Scaffold(
      body: Builder(
        builder: (context) => MediaQuery(
          data: MediaQuery.of(context)
              .copyWith(textScaler: TextScaler.linear(textScale)),
          child: child,
        ),
      ),
    ),
  ),
);

void main() {
  for (final largeText in [false, true]) {
    testWidgets('diagnostics keeps room recovery scoped (large: $largeText)', (
      tester,
    ) async {
      final harness = (await tester.runAsync(_harness))!;
      addTearDown(harness.dispose);
      final failedRoom = harness.store.parallelRooms.session(_roomTwo)!;
      failedRoom.phase = RoomConnectionPhase.failed;
      failedRoom.snapshot = null;
      final opened = <String>[];
      await tester.binding.setSurfaceSize(
        largeText ? const Size(390, 844) : const Size(800, 628),
      );
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        _app(
          DiagnosticsPage(statusStore: harness.store, onOpenRoom: opened.add),
          textScale: largeText ? 2 : 1,
        ),
      );
      expect(find.text('Room 1'), findsOneWidget);
      expect(find.text('Room 2'), findsOneWidget);
      expect(find.text('Running'), findsOneWidget);
      expect(find.text('Connection failed'), findsOneWidget);
      expect(find.text('Diagnostics unavailable'), findsOneWidget);
      expect(find.text('Default local connection is healthy'), findsNothing);
      expect(find.text('Check again'), findsOneWidget);
      final action = find.byKey(ValueKey('diagnostics-room-$_roomTwo'));
      await tester.ensureVisible(action);
      await tester.pumpAndSettle();
      await tester.tap(action);
      expect(opened, [_roomTwo]);
      expect(harness.store.parallelRooms.sessions, hasLength(2));
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('diagnostics labels an incomplete primary catalog as cached', (
    tester,
  ) async {
    final harness = (await tester.runAsync(() => _harness(rooms: 0)))!;
    addTearDown(harness.dispose);
    harness.store.primary = _snapshot('default', 0, capturedMismatch: true);
    await tester.pumpWidget(_app(DiagnosticsPage(statusStore: harness.store)));
    expect(find.text('Diagnostics data is stale'), findsOneWidget);
    expect(find.text('Last reported: Running normally'), findsOneWidget);
    expect(find.text('Running normally'), findsNothing);
    expect(find.text('Check again'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'disconnected device catalog explains its scope and opens rooms',
    (tester) async {
      final harness = (await tester.runAsync(() => _harness(rooms: 0)))!;
      addTearDown(harness.dispose);
      var openedRooms = false;
      await tester.pumpWidget(
        _app(
          NodesPage(
            settingsStore: harness.settings,
            statusStore: harness.store,
            onOpenRooms: () => openedRooms = true,
          ),
        ),
      );
      expect(find.text('This device is not connected'), findsOneWidget);
      expect(find.text('No other devices in this connection'), findsNothing);
      await tester.ensureVisible(find.text('Choose a room to connect'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Choose a room to connect'));
      expect(openedRooms, isTrue);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'empty room catalogs distinguish connecting unavailable and ready',
    (tester) async {
      final harness = (await tester.runAsync(() => _harness(rooms: 1)))!;
      addTearDown(harness.dispose);
      final room = harness.store.parallelRooms.session(_roomOne)!;
      Future<void> render() => tester.pumpWidget(
        _app(
          NodesPage(
            settingsStore: harness.settings,
            statusStore: harness.store,
          ),
        ),
      );
      room.snapshot = null;
      room.phase = RoomConnectionPhase.starting;
      await render();
      expect(find.text('Connecting to the network'), findsOneWidget);
      expect(find.text('No other devices in this connection'), findsNothing);

      room.phase = RoomConnectionPhase.failed;
      await render();
      expect(
        find.text('Device status is currently unavailable'),
        findsOneWidget,
      );
      expect(find.text('This device is not connected'), findsNothing);

      room.phase = RoomConnectionPhase.running;
      room.snapshot = DiagnosticsSnapshot.fromJson({
        ..._snapshot(_roomOne, 1).raw,
        'peers': <dynamic>[],
      });
      await render();
      expect(find.text('No other devices in this connection'), findsOneWidget);
      expect(find.text('Device status is currently unavailable'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  test(
    'room snapshots preserve scope and never reuse primary node transfer rates',
    () async {
      final harness = await _harness();
      addTearDown(harness.dispose);
      harness.store.primary = _snapshot(harness.settings.settings.networkId, 9);
      final overview = NetworkOverview.read(harness.store);
      expect(overview.runningRooms, 2);
      expect(overview.onlineCount, 3);
      expect(overview.availableCount, 3);
      expect(overview.peers.map((item) => item.identity).toSet(), hasLength(3));
      expect(overview.peers.first.transferBytesPerSecond, 8192);
      expect(
        overview.peers
            .where((item) => !item.isPrimary)
            .map((item) => item.transferBytesPerSecond),
        everyElement(isNull),
      );
      expect(overview.peers.last.roomId, _roomTwo);
      expect(overview.peers.last.processId, 102);
      expect(overview.peers.last.snapshotRevision, 8);
      expect(overview.peers.last.networkGeneration, 2);
      expect(overview.peers.last.profileId, isNotEmpty);
    },
  );

  test(
    'stale and incomplete catalogs never count as online or available',
    () async {
      final harness = await _harness(rooms: 1);
      addTearDown(harness.dispose);
      harness.store.primary = _snapshot(
        harness.settings.settings.networkId,
        9,
        capturedMismatch: true,
      );
      final room = harness.store.parallelRooms.session(_roomOne)!;
      room.snapshot = _snapshot(_roomOne, 1, stale: true);
      final overview = NetworkOverview.read(harness.store);
      expect(
        overview.scopes.map((scope) => scope.state),
        everyElement(NetworkDisplayState.stale),
      );
      expect(overview.onlineCount, 0);
      expect(overview.availableCount, 0);
      expect(overview.peers, hasLength(2));
      expect(overview.needsAttention, isTrue);
    },
  );

  test(
    'one room reported by primary and parallel owners is displayed once',
    () async {
      final harness = await _harness(rooms: 1);
      addTearDown(harness.dispose);
      harness.store.primary = _snapshot(_roomOne, 1);
      expect(NetworkOverview.read(harness.store).peers, hasLength(1));
    },
  );

  testWidgets(
    'home shows running rooms and routes duplicate-node rows by room identity',
    (tester) async {
      tester.view.physicalSize = const Size(900, 1200);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final harness = (await tester.runAsync(() => _harness()))!;
      addTearDown(harness.dispose);
      final openedRooms = <String>[];
      var openedPrimaryPeer = false;
      await tester.pumpWidget(
        _app(
          DashboardPage(
            settingsStore: harness.settings,
            statusStore: harness.store,
            onOpenRoom: openedRooms.add,
            onOpenPeer: (_) => openedPrimaryPeer = true,
            onOpenRooms: () {},
          ),
        ),
      );
      expect(find.text('Rooms connected'), findsOneWidget);
      expect(find.text('P2WLAN is not running'), findsNothing);
      expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
      expect(find.byKey(const Key('dashboard-stop-button')), findsNothing);
      final overview = NetworkOverview.read(harness.store);
      for (final item in overview.peers) {
        await tester.ensureVisible(
          find.byKey(Key('home-device-row-${item.identity}')),
        );
        await tester.tap(find.byKey(Key('home-device-row-${item.identity}')));
      }
      expect(openedRooms, [_roomOne, _roomTwo]);
      expect(openedPrimaryPeer, isFalse);
      await tester.ensureVisible(find.byKey(const Key('network-scope-picker')));
      await tester.tap(find.byKey(const Key('network-scope-picker')));
      await tester.pumpAndSettle();
      await tester.tap(
        find.widgetWithText(CheckedPopupMenuItem<String>, 'Room 2'),
      );
      await tester.pumpAndSettle();
      expect(find.text('Shared laptop'), findsOneWidget);
      expect(
        find.byKey(Key('home-device-row-${overview.peers.last.identity}')),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'devices scope, search and row actions stay room-specific at large text',
    (tester) async {
      tester.view.physicalSize = const Size(390, 1000);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final harness = (await tester.runAsync(() => _harness()))!;
      addTearDown(harness.dispose);
      final openedRooms = <String>[];
      await tester.pumpWidget(
        _app(
          NodesPage(
            settingsStore: harness.settings,
            statusStore: harness.store,
            onOpenRoom: openedRooms.add,
            onOpenRooms: () {},
          ),
          textScale: 1.6,
        ),
      );
      expect(find.byKey(const Key('nodes-local-row')), findsNothing);
      expect(find.text('2 device connections · 2 online'), findsOneWidget);
      final overview = NetworkOverview.read(harness.store);
      for (final item in overview.peers) {
        final row = find.byKey(Key('node-row-${item.identity}'));
        await tester.ensureVisible(row);
        await tester.pumpAndSettle();
        expect(row.hitTestable(), findsOneWidget);
        await tester.tap(row);
      }
      expect(openedRooms, [_roomOne, _roomTwo]);
      expect(find.byType(Dialog), findsNothing);
      final search = find.byKey(const Key('nodes-search-field'));
      await tester.ensureVisible(search);
      await tester.pumpAndSettle();
      await tester.enterText(search, 'Room 2');
      await tester.pump();
      expect(find.text('Shared laptop'), findsOneWidget);
      final name = tester.widget<Text>(find.text('Shared laptop'));
      expect(name.style!.fontSize, greaterThanOrEqualTo(14));
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('online-first orders the combined room catalog stably', (
    tester,
  ) async {
    final harness = (await tester.runAsync(() => _harness()))!;
    addTearDown(harness.dispose);
    harness.store.primary = _snapshot(
      harness.settings.settings.networkId,
      9,
      online: false,
    );
    harness.store.parallelRooms.session(_roomOne)!.snapshot = _snapshot(
      _roomOne,
      1,
      online: false,
    );
    await tester.pumpWidget(
      _app(
        NodesPage(settingsStore: harness.settings, statusStore: harness.store),
      ),
    );
    final peers = NetworkOverview.read(harness.store).peers;
    final primary = find.byKey(const Key('node-row-same-node'));
    final firstRoom = find.byKey(
      Key('node-row-${peers.firstWhere((p) => p.roomId == _roomOne).identity}'),
    );
    final secondRoom = find.byKey(
      Key('node-row-${peers.firstWhere((p) => p.roomId == _roomTwo).identity}'),
    );
    expect(
      tester.getTopLeft(secondRoom).dy,
      lessThan(tester.getTopLeft(primary).dy),
    );
    expect(
      tester.getTopLeft(primary).dy,
      lessThan(tester.getTopLeft(firstRoom).dy),
    );
  });

  testWidgets(
    'selected but unverified direct path stays probing in filters and detail actions',
    (tester) async {
      final harness = (await tester.runAsync(() => _harness(rooms: 0)))!;
      addTearDown(harness.dispose);
      final raw = Map<String, dynamic>.from(
        _snapshot(harness.settings.settings.networkId, 9).raw,
      );
      final peer = Map<String, dynamic>.from(
        (raw['peers'] as List).single as Map,
      );
      peer['state'] = 'idle';
      peer['current_path_selection'] = {
        'path': 'direct',
        'direct_confirmed': true,
      };
      raw['peers'] = [peer];
      harness.store.primary = DiagnosticsSnapshot.fromJson(raw);
      expect(harness.store.primary!.peers.single.path, 'direct');
      expect(harness.store.primary!.peers.single.isDirectVerified, isFalse);
      await tester.pumpWidget(
        _app(
          NodesPage(
            settingsStore: harness.settings,
            statusStore: harness.store,
          ),
        ),
      );
      final row = find.byKey(const Key('node-row-same-node'));
      expect(
        find.descendant(of: row, matching: find.text('probing')),
        findsOneWidget,
      );
      Future<void> selectFilter(String name) async {
        await tester.ensureVisible(
          find.byKey(const Key('nodes-filter-button')),
        );
        await tester.pumpAndSettle();
        await tester.tap(find.byKey(const Key('nodes-filter-button')));
        await tester.pumpAndSettle();
        await tester.tap(find.byKey(Key('nodes-filter-$name')));
        await tester.pumpAndSettle();
      }

      await selectFilter('direct');
      expect(row, findsNothing);
      await selectFilter('attention');
      expect(row, findsOneWidget);
      await tester.ensureVisible(row);
      await tester.pumpAndSettle();
      await tester.tap(row);
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('peer-detail-header')), findsOneWidget);
      expect(
        find.byKey(const Key('node-detail-speedtest-same-node')),
        findsNothing,
      );
      expect(tester.takeException(), isNull);
    },
  );

  for (final mismatchedRevision in [false, true]) {
    testWidgets(
      'primary stale presentation stays consistent (revision mismatch: $mismatchedRevision)',
      (tester) async {
        final harness = (await tester.runAsync(() => _harness(rooms: 0)))!;
        addTearDown(harness.dispose);
        harness.store.primary = _snapshot(
          harness.settings.settings.networkId,
          9,
          stale: !mismatchedRevision,
          capturedMismatch: mismatchedRevision,
        );
        await tester.pumpWidget(
          _app(
            DashboardPage(
              settingsStore: harness.settings,
              statusStore: harness.store,
            ),
          ),
        );
        expect(
          find.byKey(const Key('dashboard-count-available')),
          findsNothing,
        );
        expect(find.text('Shared laptop'), findsOneWidget);
        expect(find.text('12 ms'), findsNothing);
        expect(find.text('8 KB/s'), findsNothing);
        expect(find.text('Network components'), findsNothing);
        final homePeer = find.byKey(const Key('home-device-row-same-node'));
        expect(
          find.descendant(of: homePeer, matching: find.text('Stale')),
          findsOneWidget,
        );
        await tester.pumpWidget(
          _app(
            NodesPage(
              settingsStore: harness.settings,
              statusStore: harness.store,
            ),
          ),
        );
        final local = find.byKey(const Key('nodes-local-row'));
        expect(
          find.descendant(of: local, matching: find.text('Connected')),
          findsNothing,
        );
        expect(
          find.descendant(of: local, matching: find.text('Stale')),
          findsOneWidget,
        );
        expect(find.text('12 ms'), findsNothing);
        final peer = find.byKey(const Key('node-row-same-node'));
        await tester.ensureVisible(peer);
        await tester.pumpAndSettle();
        await tester.tap(peer);
        await tester.pumpAndSettle();
        final detail = find.byKey(const Key('peer-detail-header'));
        expect(
          find.descendant(of: detail, matching: find.text('Stale')),
          findsOneWidget,
        );
        expect(
          find.byKey(const Key('node-detail-speedtest-same-node')),
          findsNothing,
        );
        expect(find.text('12 ms'), findsNothing);
        expect(tester.takeException(), isNull);
      },
    );
  }

  testWidgets(
    'desktop devices and home preserve full path metrics at 200 percent text',
    (tester) async {
      tester.view.physicalSize = const Size(800, 1100);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final harness = (await tester.runAsync(() => _harness(rooms: 0)))!;
      addTearDown(harness.dispose);
      harness.store.primary = _snapshot(harness.settings.settings.networkId, 9);
      for (final child in <Widget>[
        NodesPage(settingsStore: harness.settings, statusStore: harness.store),
        DashboardPage(
          settingsStore: harness.settings,
          statusStore: harness.store,
        ),
      ]) {
        // Match the true 800px shell after the 196px sidebar and divider.
        await tester.pumpWidget(
          _app(
            Row(
              children: [
                const SizedBox(width: 197),
                Expanded(child: child),
              ],
            ),
            textScale: 2,
          ),
        );
        expect(tester.takeException(), isNull);
        final latency = find.textContaining('12 ms');
        expect(latency, findsOneWidget);
        expect(
          tester.widget<Text>(latency).overflow,
          isNot(TextOverflow.ellipsis),
        );
      }
    },
  );

  testWidgets('large phone text keeps the local identity and IP complete', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final harness = (await tester.runAsync(() => _harness(rooms: 0)))!;
    addTearDown(harness.dispose);
    harness.store.primary = _snapshot(harness.settings.settings.networkId, 9);
    await tester.pumpWidget(
      _app(
        NodesPage(settingsStore: harness.settings, statusStore: harness.store),
        textScale: 2,
      ),
    );
    final local = find.byKey(const Key('nodes-local-row'));
    for (final value in ['Work laptop', '10.21.9.2', 'connected']) {
      final text = find.descendant(of: local, matching: find.text(value));
      expect(text, findsOneWidget);
      expect(
        tester.renderObject<RenderParagraph>(text).didExceedMaxLines,
        isFalse,
      );
    }
    expect(tester.takeException(), isNull);
  });

  for (final platform in ['ios', 'web']) {
    testWidgets(
      '$platform device management opens room roster without a local service',
      (tester) async {
        final harness = (await tester.runAsync(() => _harness(rooms: 0)))!;
        addTearDown(harness.dispose);
        var opened = false;
        await tester.pumpWidget(
          _app(
            NodesPage(
              settingsStore: harness.settings,
              statusStore: harness.store,
              capabilities: PlatformCapabilities.fromPlatform(platform),
              onOpenRooms: () => opened = true,
            ),
          ),
        );
        expect(find.byKey(const Key('nodes-local-row')), findsNothing);
        await tester.tap(find.byKey(const Key('remote-nodes-open-rooms')));
        expect(opened, isTrue);
      },
    );
  }

  testWidgets('wide and compact sidebar use the same room status projection', (
    tester,
  ) async {
    final harness = (await tester.runAsync(() => _harness(rooms: 1)))!;
    addTearDown(harness.dispose);
    final strings = AppStrings.fromCode('en');
    final expected = networkOverviewStatus(
      strings,
      NetworkOverview.read(harness.store),
    );
    await tester.pumpWidget(
      _app(
        Row(
          children: [
            DesktopSidebar(
              selected: P2WlanSection.home,
              strings: strings,
              statusStore: harness.store,
              onSelect: (_) {},
              onFooterTap: () {},
            ),
            AppNavRail(
              selected: P2WlanSection.home,
              iconOnly: true,
              strings: strings,
              statusStore: harness.store,
              onSelect: (_) {},
              onFooterTap: () {},
            ),
          ],
        ),
      ),
    );
    expect(find.text(expected.$2), findsOneWidget);
    expect(
      find.bySemanticsLabel('${expected.$2}, ${expected.$3}'),
      findsWidgets,
    );
    expect(tester.takeException(), isNull);
  });
  testWidgets('expired primary authentication offers direct sign in', (
    tester,
  ) async {
    final harness = (await tester.runAsync(() => _harness(rooms: 0)))!;
    addTearDown(harness.dispose);
    final raw = Map<String, dynamic>.from(
      _snapshot(harness.settings.settings.networkId, 9).raw,
    );
    raw['health'] = {'status': 'degraded', 'reauth_required': true};
    harness.store.primary = DiagnosticsSnapshot.fromJson(raw);
    var signedIn = false;
    var troubleshooting = false;
    await tester.pumpWidget(
      _app(
        DashboardPage(
          settingsStore: harness.settings,
          statusStore: harness.store,
          onReauthenticate: () => signedIn = true,
          onOpenTroubleshooting: () => troubleshooting = true,
        ),
      ),
    );
    await tester.ensureVisible(find.byKey(const Key('home-reauthenticate')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('home-reauthenticate')));
    expect(signedIn, isTrue);
    expect(troubleshooting, isFalse);
  });
  test('primary stays connected while parallel rooms are stopping', () async {
    final harness = await _harness(rooms: 1);
    addTearDown(harness.dispose);
    harness.store.primary = _snapshot(harness.settings.settings.networkId, 9);
    final room = harness.store.parallelRooms.session(_roomOne)!;
    room.phase = RoomConnectionPhase.stopping;
    room.snapshot = null;
    final overview = NetworkOverview.read(harness.store);
    final status = networkOverviewStatus(AppStrings.fromCode('en'), overview);
    expect(overview.runningRooms, 0);
    expect(overview.hasRunningNetwork, isTrue);
    expect(status.$2, 'Network OK');
    expect(status.$3, 'Local network running; rooms disconnecting');
    expect(overview.onlineCount, 1);
  });

  test(
    'fresh parallel room survives a duplicate stale primary catalog',
    () async {
      final harness = await _harness(rooms: 1);
      addTearDown(harness.dispose);
      harness.store.primary = _snapshot(_roomOne, 1, stale: true);
      final overview = NetworkOverview.read(harness.store);
      expect(overview.runningRooms, 1);
      expect(overview.availableCount, 1);
      expect(overview.peers, hasLength(1));
      expect(overview.peers.single.isPrimary, isFalse);
      expect(overview.peers.single.transferBytesPerSecond, isNull);
      expect(overview.needsAttention, isFalse);
    },
  );
}
