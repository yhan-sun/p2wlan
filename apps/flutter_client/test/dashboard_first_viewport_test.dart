import 'dart:convert';
import 'dart:io';

import 'package:flutter/gestures.dart';
import 'package:flutter/foundation.dart';
import 'package:flutter/material.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/app/app_strings.dart';
import 'package:p2wlan_flutter_client/app/app_theme.dart';
import 'package:p2wlan_flutter_client/app/app_tokens.dart';
import 'package:p2wlan_flutter_client/app/navigation.dart';
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
import 'package:p2wlan_flutter_client/core/traffic/traffic_history_store.dart';
import 'package:p2wlan_flutter_client/features/dashboard/dashboard_page.dart';
import 'package:p2wlan_flutter_client/shared/widgets/traffic_history_scope.dart';

String _roomId(int number) => 'room-${number.toString().padLeft(32, '0')}';

DiagnosticsSnapshot _snapshot(String network, int subnet) =>
    DiagnosticsSnapshot.fromJson({
      'network_id': network,
      'node_id': 'local-$subnet',
      'virtual_ip': '10.21.$subnet.2',
      'revision': 1,
      'captured_revision': 1,
      'network_generation': subnet,
      'runtime_incarnation': 1,
      'health': {'status': 'healthy', 'control_connected': true},
      'stats': {
        'total_peers': 2,
        'total_bytes_sent': 1024,
        'total_bytes_received': 2048,
      },
      'peers': [
        for (var index = 1; index <= 2; index++)
          {
            'node_id': 'peer-$subnet-$index',
            'device_name': '演示设备 $index',
            'virtual_ip': '10.21.$subnet.${index + 2}',
            'online': true,
            'bytes_sent': 1024,
            'bytes_received': 2048,
            'state': 'direct',
            'active_path': 'direct',
            'direct': {'latency_ms': 12, 'last_success_age_ms': 0},
          },
      ],
    });

class _RoomRuntime implements RoomRuntime {
  _RoomRuntime(this.plan);
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
      _snapshot(plan.room.id, plan.room.id == _roomId(1) ? 1 : 2);
  @override
  void close() {}
}

class _Status extends StatusStore {
  _Status(SettingsStore settings, ParallelRooms rooms)
    : super(
        settingsStore: settings,
        parallelRooms: rooms,
        diagnosticsApi: DiagnosticsApi(),
        enableEventPolling: false,
        enableFreshnessTimer: false,
      );
  DiagnosticsSnapshot? primary;

  void updatePrimary(DiagnosticsSnapshot snapshot) {
    primary = snapshot;
    notifyListeners();
  }

  @override
  DiagnosticsSnapshot? get snapshot => primary;
  @override
  bool get healthReachable => primary != null;
  @override
  bool get daemonReachable => primary != null;
}

class _Fixture {
  _Fixture(this.directory, this.settings, this.status);
  final Directory directory;
  final SettingsStore settings;
  final _Status status;
  void dispose() {
    status.dispose();
    settings.dispose();
    directory.deleteSync(recursive: true);
  }
}

Future<_Fixture> _fixture(String state) async {
  final directory = await Directory.systemTemp.createTemp(
    'dashboard-viewport-',
  );
  final settings = SettingsStore(
    settingsFile: File('${directory.path}/settings.json'),
    tokenRepository: InMemorySecureTokenRepository(),
  );
  await settings.load();
  final token =
      'a.${base64Url.encode(utf8.encode(jsonEncode({'user_id': 'demo-user'})))}.b';
  await settings.updateSettings(
    settings.settings.copyWith(
      controlServer: 'https://control.example.com',
      authToken: token,
      languageCode: 'zh',
      deviceName: '演示设备',
    ),
  );
  final rooms = ParallelRooms(
    readSettings: () => settings.settings,
    runtimeFactory: _RoomRuntime.new,
    supported: true,
    refreshInterval: Duration.zero,
  );
  final status = _Status(settings, rooms);
  if (state == 'primary') {
    status.primary = _snapshot(settings.settings.networkId, 9);
  } else if (state != 'stopped') {
    for (var number = 1; number <= 2; number++) {
      final room = FriendRoom(
        id: _roomId(number),
        code: '$number'.padLeft(8, '0'),
        name: number == 1 ? '朋友联机' : '工作设备',
        cidr: '10.21.$number.0/24',
        ownerId: 'demo-user',
        role: 'owner',
        locked: false,
      );
      expect((await rooms.connect(room)).ok, isTrue);
    }
    if (state == 'attention') {
      final failed = rooms.session(_roomId(2))!;
      failed.phase = RoomConnectionPhase.failed;
      failed.snapshot = null;
      failed.message = '运行时或路由不可用；未显示过期的在线状态';
    }
  }
  return _Fixture(directory, settings, status);
}

Widget _host(_Fixture fixture, bool phone, {TrafficHistoryStore? history}) {
  Widget child = MaterialApp(
    theme: AppTheme.lightTheme,
    home: AppStringsScope(
      strings: AppStrings.fromCode('zh'),
      child: P2WlanShell(
        settingsStore: fixture.settings,
        statusStore: fixture.status,
        capabilities: PlatformCapabilities.fromPlatform(
          phone ? 'android' : 'macos',
        ),
      ),
    ),
  );
  if (history != null) {
    child = TrafficHistoryScope(
      store: history,
      settings: fixture.settings.settings,
      onRefresh: () {},
      child: child,
    );
  }
  return child;
}

void main() {
  testWidgets('desktop Home diagnoses the selected verified path', (
    tester,
  ) async {
    final fixture = (await tester.runAsync(() => _fixture('primary')))!;
    addTearDown(fixture.dispose);
    var devicesOpened = 0;
    final raw = fixture.status.primary!.raw;
    fixture.status.primary = DiagnosticsSnapshot.fromJson({
      ...raw,
      'peers': [
        {
          'node_id': 'verified-relay',
          'device_name': 'Verified relay peer',
          'virtual_ip': '10.21.9.12',
          'online': true,
          'state': 'relay',
          'active_path': 'relay',
          'relay_confirmed_endpoint': '127.0.0.1:8080',
          'relay_confirmed_generation': 9,
          'relay': {
            'last_success_age_ms': 100,
            'rtt_ewma_ms': 26,
            'jitter_ms': 4,
          },
          'path_observability': {
            'schema_version': 1,
            'current_path': 'relay',
            'last_path_change_reason': 'direct_first_deadline',
            'transition_reason': 'relay_health_observed',
            'direct_state': 'probing',
            'transitions': [
              {'event_kind': 'direct_probe_started', 'age_ms': 4100},
            ],
          },
        },
        {
          'node_id': 'probing',
          'device_name': 'Probing peer',
          'virtual_ip': '10.21.9.13',
          'online': true,
          'state': 'hole_punching',
          'direct': {'rtt_ewma_ms': 1, 'jitter_ms': 2},
        },
      ],
    });
    await tester.pumpWidget(
      MaterialApp(
        theme: AppTheme.lightTheme.copyWith(platform: TargetPlatform.macOS),
        home: AppStringsScope(
          strings: AppStrings.fromCode('en'),
          child: Scaffold(
            body: DashboardPage(
              settingsStore: fixture.settings,
              statusStore: fixture.status,
              capabilities: PlatformCapabilities.fromPlatform('macos'),
              onOpenDevices: () => devicesOpened++,
            ),
          ),
        ),
      ),
    );
    final median = find.byKey(const Key('home-live-rtt'));
    expect(
      find.descendant(of: median, matching: find.text('26 ms')),
      findsOneWidget,
    );
    final breakdown = find.byKey(const Key('home-path-breakdown'));
    final segments = find.descendant(
      of: breakdown,
      matching: find.byType(ColoredBox),
    );
    expect(segments, findsNWidgets(2));
    final segmentWidth = tester.getSize(breakdown).width / 2;
    for (final segment in segments.evaluate()) {
      final size = tester.getSize(find.byWidget(segment.widget));
      expect(size.height, AppTokens.space4);
      expect(size.width, closeTo(segmentWidth, 0.01));
    }
    final devicesAction = find.byKey(const Key('home-view-all-devices'));
    expect(
      find.descendant(of: devicesAction, matching: find.text('View devices')),
      findsOneWidget,
    );
    await tester.tap(devicesAction);
    expect(devicesOpened, 1);
    expect(find.text('Jitter'), findsNothing);
    final peer = NetworkOverview.read(fixture.status).peers.first;
    final row = find.byKey(Key('home-device-row-${peer.identity}'));
    await tester.tap(row, buttons: kSecondaryMouseButton);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Diagnostics'));
    await tester.pumpAndSettle();
    expect(find.text('4 ms'), findsOneWidget);
    expect(find.text('2 ms'), findsNothing);
    expect(find.text('Direct connection timed out'), findsOneWidget);
    expect(find.text('Direct probe started'), findsOneWidget);
    expect(find.text('Packet loss'), findsOneWidget);

    final observed = fixture.status.primary!.raw;
    final peers = (observed['peers'] as List).cast<Map<String, dynamic>>();
    fixture.status.updatePrimary(
      DiagnosticsSnapshot.fromJson({
        ...observed,
        'peers': [
          {
            ...peers.first,
            'path_observability': {
              'schema_version': 1,
              'current_path': 'relay',
              'last_path_change_reason': 'relay_peer_confirmed',
              'transition_reason': 'relay_health_observed',
            },
          },
          peers.last,
        ],
      }),
    );
    await tester.pumpAndSettle();
    expect(find.text('Relay fallback reason'), findsOneWidget);
    expect(find.text('Direct connection timed out'), findsNothing);
    expect(find.text('Relay peer confirmed'), findsNothing);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('Home invitation action names and opens its selected room', (
    tester,
  ) async {
    final fixture = (await tester.runAsync(() => _fixture('normal')))!;
    addTearDown(fixture.dispose);
    var roomLists = 0;
    final opened = <String>[];
    await tester.pumpWidget(
      MaterialApp(
        theme: AppTheme.lightTheme,
        home: AppStringsScope(
          strings: AppStrings.fromCode('zh'),
          child: Scaffold(
            body: DashboardPage(
              settingsStore: fixture.settings,
              statusStore: fixture.status,
              onOpenRooms: () => roomLists++,
              onOpenRoom: opened.add,
            ),
          ),
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('选择房间邀请'), findsOneWidget);
    final action = find.byKey(const Key('home-room-action'));
    await tester.tap(action);
    expect(roomLists, 1);
    expect(opened, isEmpty);
    await tester.tap(find.byKey(const Key('network-scope-picker')));
    await tester.pumpAndSettle();
    await tester.tap(find.widgetWithText(CheckedPopupMenuItem<String>, '工作设备'));
    await tester.pumpAndSettle();
    expect(find.text('邀请设备'), findsOneWidget);
    await tester.tap(action);
    expect(opened, [_roomId(2)]);
    expect(roomLists, 1);
    final details = find.byKey(const Key('home-room-connections-details'));
    await tester.tap(details);
    await tester.pumpAndSettle();
    final room = find.byKey(Key('home-network-scope-room:${_roomId(2)}'));
    await tester.ensureVisible(room);
    await tester.pumpAndSettle();
    await tester.tap(room);
    expect(opened, [_roomId(2), _roomId(2)]);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  for (final size in [const Size(800, 628), const Size(390, 844)]) {
    for (final state in ['normal', 'attention', 'primary']) {
      testWidgets('Home first viewport shows two devices $size $state', (
        tester,
      ) async {
        final phone = size.width < 600;
        debugDefaultTargetPlatformOverride = phone
            ? TargetPlatform.android
            : TargetPlatform.macOS;
        try {
          await tester.binding.setSurfaceSize(size);
          addTearDown(() => tester.binding.setSurfaceSize(null));
          final fixture = (await tester.runAsync(() => _fixture(state)))!;
          addTearDown(fixture.dispose);
          await tester.pumpWidget(_host(fixture, phone));
          await tester.pumpAndSettle();
          final viewport = tester.getRect(
            find
                .descendant(
                  of: find.byType(DashboardPage),
                  matching: find.byType(ListView),
                )
                .first,
          );
          final rows = find.byWidgetPredicate(
            (widget) =>
                widget is InkWell &&
                widget.key is ValueKey &&
                (widget.key as ValueKey).value.toString().startsWith(
                  'home-device-row-',
                ),
          );
          expect(rows, findsWidgets);
          for (var index = 0; index < 2; index++) {
            final bounds = tester.getRect(rows.at(index));
            expect(bounds.top, greaterThanOrEqualTo(viewport.top));
            expect(
              bounds.bottom,
              lessThanOrEqualTo(viewport.bottom),
              reason:
                  'device ${index + 1} must be fully visible without scrolling',
            );
            expect(rows.at(index).hitTestable(), findsOneWidget);
          }
          expect(find.byKey(const Key('home-room-shortcut')), findsNothing);
          if (state != 'primary') {
            expect(
              find.byKey(Key('home-network-scope-room:${_roomId(1)}')),
              findsNothing,
            );
            expect(find.byType(FilledButton), findsOneWidget);
          }
          if (state == 'attention') {
            expect(find.byKey(const Key('home-room-issue')), findsOneWidget);
            expect(find.byIcon(Icons.warning_amber_rounded), findsOneWidget);
          }
          expect(tester.takeException(), isNull);
          await tester.pumpWidget(const SizedBox.shrink());
        } finally {
          debugDefaultTargetPlatformOverride = null;
        }
      });
    }
  }

  testWidgets(
    'Home stopped state hides empty traffic and shows only saved history entry',
    (tester) async {
      final fixture = (await tester.runAsync(() => _fixture('stopped')))!;
      addTearDown(fixture.dispose);
      await tester.pumpWidget(_host(fixture, true));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('home-traffic-current-total')), findsNothing);
      expect(find.byKey(const Key('home-traffic-history-entry')), findsNothing);
      final history = TrafficHistoryStore(persistent: false);
      addTearDown(history.dispose);
      await tester.runAsync(history.load);
      fixture.status.primary = _snapshot(
        fixture.settings.settings.networkId,
        9,
      );
      history.observe(
        settings: fixture.settings.settings,
        scopes: NetworkOverview.read(fixture.status).scopes,
      );
      fixture.status.primary = null;
      await tester.pumpWidget(_host(fixture, true, history: history));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('home-traffic-current-total')), findsNothing);
      final entry = find.byKey(const Key('home-traffic-history-entry'));
      expect(entry, findsOneWidget);
      await tester.ensureVisible(entry);
      await tester.tap(entry);
      await tester.pumpAndSettle();
      expect(find.text('流量详情'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
}
