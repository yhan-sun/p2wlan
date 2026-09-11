import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:p2wlan_flutter_client/app/navigation.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/rooms/parallel_rooms.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/capabilities/platform_capabilities.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/rooms/room_api.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/rooms/rooms_page.dart';

final _token =
    'a.${base64Url.encode(utf8.encode(jsonEncode({'user_id': 'member'})))}.b';

const _roomId = 'room-0123456789abcdef0123456789abcdef';
Map<String, dynamic> _room(String role) => {
  'id': _roomId,
  'room_code': '12345678',
  'name': '朋友房间',
  'cidr': '10.21.1.0/24',
  'owner_id': 'owner',
  'role': role,
  'join_locked': false,
};

class _FakeRoomApi extends RoomApi {
  _FakeRoomApi({this.role = 'owner', this.empty = false, this.controls = false})
    : super(server: 'https://control.example', token: _token);
  final String role;
  final bool controls;
  String accessState = 'allowed';
  bool approvalRequired = false;
  bool empty;
  bool ownerOnline = false;
  bool deviceOnline = true;
  String? joinError;
  final calls = <String>[];
  int listCalls = 0;
  @override
  Future<List<FriendRoom>> list() async {
    listCalls++;
    userId = role == 'owner' ? 'owner' : 'member';
    return empty
        ? []
        : [
            FriendRoom.fromJson({
              ..._room(role),
              if (controls) 'device_controls_version': 1,
            }),
          ];
  }

  @override
  Future<RoomRoster> roster(String room) async => RoomRoster.fromJson({
    'room': {..._room(role), if (controls) 'device_controls_version': 1},
    'device_approval_required': approvalRequired,
    'device_access': controls
        ? [
            {
              'id': 'access-one',
              'user_id': 'member',
              'public_key': 'key-one',
              'device_name': '好友电脑',
              'device_id': 'device-1',
              'state': accessState,
              'blocked_by': 'owner',
            },
          ]
        : [],
    'members': [
      {'user_id': 'owner', 'role': 'owner', 'username': '房主小林'},
      {'user_id': 'member', 'role': 'member', 'username': '阿明'},
    ],
    'devices': [
      {
        'id': 'device-1',
        'user_id': ownerOnline ? 'owner' : 'member',
        'device_name': '好友电脑',
        'virtual_ip': '10.21.1.3',
        'online': deviceOnline,
      },
    ],
    'banned_user_ids': [],
  });
  @override
  Future<Map<String, dynamic>> request(
    String method,
    List<String> segments, [
    Map<String, dynamic>? payload,
  ]) async {
    calls.add('$method ${segments.join('/')} ${jsonEncode(payload)}');
    if (method == 'POST' && segments.contains('device-access')) {
      accessState = segments.last == 'block' ? 'blocked' : 'paused';
    }
    if (method == 'PUT' && segments.last == 'device-policy') {
      approvalRequired = payload?['require_approval'] == true;
    }
    if (method == 'GET' && segments.last == 'invites') return {'invites': []};
    return {'success': true};
  }

  @override
  Future<FriendRoom> create(String name, String password) async {
    calls.add('create:$name:$password');
    empty = false;
    return FriendRoom.fromJson(_room('owner'));
  }

  @override
  Future<FriendRoom> join(
    String code, {
    String? password,
    String? invitation,
  }) async {
    calls.add('join:$code:$password:$invitation');
    if (joinError != null) throw RoomException(joinError!);
    empty = false;
    return FriendRoom.fromJson(_room('member'));
  }
}

class _PulsingStatusStore extends StatusStore {
  _PulsingStatusStore({
    required super.parallelRooms,
    required super.settingsStore,
    required super.diagnosticsApi,
    super.enableFreshnessTimer = false,
  });
  void pulse() => notifyListeners();
}

class _RoomRuntime implements RoomRuntime {
  _RoomRuntime(this.snapshot) {
    instances.add(this);
  }
  static final instances = <_RoomRuntime>[];
  DiagnosticsSnapshot snapshot;
  int statusCalls = 0;
  @override
  Future<bool> exists() async => false;
  @override
  Future<DaemonCommandResult> start() async =>
      const DaemonCommandResult(ok: true, message: '');
  @override
  Future<DaemonCommandResult> stop() async =>
      const DaemonCommandResult(ok: true, message: '');
  @override
  Future<DiagnosticsSnapshot> status() async {
    statusCalls++;
    return snapshot;
  }

  @override
  void close() {}
}

DiagnosticsSnapshot _snapshot({bool stale = false, bool verified = true}) =>
    DiagnosticsSnapshot.fromJson({
      'network_id': _roomId,
      'virtual_ip': '10.21.1.2',
      'node_id': 'local',
      'peer_snapshot_stale': stale,
      'peers': [
        {
          'node_id': 'remote',
          'device_name': '好友电脑',
          'virtual_ip': '10.21.1.3',
          'online': true,
          'active_path': verified ? 'direct' : null,
          'state': verified ? 'direct' : 'connecting',
          'direct': {'latency_ms': 18, 'last_success_age_ms': 0},
        },
        {
          'node_id': 'discovered',
          'device_name': '新发现的电脑',
          'virtual_ip': '10.21.1.4',
          'online': true,
          'remote_relay_latency_ms': 3,
        },
      ],
    });

void main() {
  Future<_FakeRoomApi> pump(
    WidgetTester tester, {
    String role = 'owner',
    bool empty = false,
    Uri? invitation,
    DiagnosticsSnapshot? snapshot,
    bool shell = false,
    bool enterRoom = true,
    bool enableDaemonPolling = false,
    bool controls = false,
    void Function(VoidCallback)? onStatusPulse,
  }) async {
    final dir = await tester.runAsync(
      () => Directory.systemTemp.createTemp('p2wlan-rooms-ui-'),
    );
    final settings = SettingsStore(
      settingsFile: File('${dir!.path}/settings.json'),
      tokenRepository: InMemorySecureTokenRepository(),
    );
    await tester.runAsync(() async {
      await settings.load();
      await settings.updateSettings(
        AppSettings(
          controlServer: 'https://control.example',
          authToken: _token,
          onboardingCompleted: true,
        ),
      );
    });
    final parallel = ParallelRooms(
      readSettings: () => settings.settings,
      supported: snapshot != null,
      refreshInterval: enableDaemonPolling
          ? const Duration(seconds: 5)
          : Duration.zero,
      runtimeFactory: (_) => _RoomRuntime(snapshot!),
    );
    if (snapshot != null) {
      await parallel.connect(FriendRoom.fromJson(_room(role)));
    }
    final status = _PulsingStatusStore(
      parallelRooms: parallel,
      settingsStore: settings,
      diagnosticsApi: DiagnosticsApi(),
      enableFreshnessTimer: false,
    );
    onStatusPulse?.call(status.pulse);
    final api = _FakeRoomApi(role: role, empty: empty, controls: controls);
    addTearDown(() {
      api.close();
      status.dispose();
      settings.dispose();
      dir.deleteSync(recursive: true);
    });
    await tester.pumpWidget(
      MaterialApp(
        home: shell
            ? P2WlanShell(
                settingsStore: settings,
                statusStore: status,
                roomInvitation: invitation,
                capabilities: PlatformCapabilities.fromPlatform('ios'),
              )
            : RoomsPage(
                settingsStore: settings,
                statusStore: status,
                api: api,
                capabilities: PlatformCapabilities.fromPlatform('ios'),
                initialInvitation: invitation,
              ),
      ),
    );
    await tester.pumpAndSettle();
    if (enterRoom && !empty && invitation == null && !shell) {
      await tester.tap(find.byKey(const ValueKey('room-card-$_roomId')));
      await tester.pumpAndSettle();
    }
    return api;
  }

  testWidgets(
    'stable room refresh is not starved by one-second status notifications',
    (tester) async {
      late VoidCallback pulse;
      final api = await pump(
        tester,
        enterRoom: false,
        onStatusPulse: (value) => pulse = value,
      );
      final before = api.listCalls;
      for (var second = 0; second < 16; second++) {
        pulse();
        await tester.pump(const Duration(seconds: 1));
        await tester.pump();
      }
      expect(api.listCalls - before, greaterThanOrEqualTo(3));
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'saving the existing IP does not issue a mutation or ask for reconnect',
    (tester) async {
      final api = await pump(tester, controls: true);
      final menu = find.byTooltip('管理设备');
      await tester.ensureVisible(menu);
      await tester.tap(menu);
      await tester.pumpAndSettle();
      await tester.tap(find.text('分配 IP'));
      await tester.pumpAndSettle();
      await tester.tap(find.widgetWithText(FilledButton, '确认'));
      await tester.pumpAndSettle();
      expect(
        api.calls.where(
          (call) => call.startsWith('PATCH') && call.contains('/devices/'),
        ),
        isEmpty,
      );
      expect(find.text('地址未变化，无需重新连接'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'member can remotely disconnect only their device with an explicit scope',
    (tester) async {
      final api = await pump(tester, role: 'member', controls: true);
      final menu = find.byTooltip('管理设备');
      await tester.ensureVisible(menu);
      await tester.pumpAndSettle();
      await tester.tap(menu);
      await tester.pumpAndSettle();
      expect(find.text('分配 IP'), findsNothing);
      await tester.tap(find.text('断开此设备'));
      await tester.pumpAndSettle();
      expect(find.textContaining('其他设备保持连接'), findsOneWidget);
      expect(api.calls.where((call) => call.contains('/disconnect')), isEmpty);
      await tester.tap(find.text('确认'));
      await tester.pumpAndSettle();
      expect(
        api.calls.where(
          (call) => call.contains('device-access/access-one/disconnect'),
        ),
        hasLength(1),
      );
      expect(find.text('已断开'), findsOneWidget);
    },
  );

  testWidgets('owner can enable approval and approve a pending device', (
    tester,
  ) async {
    final api = await pump(tester, controls: true);
    api.accessState = 'pending';
    await tester.pump(const Duration(seconds: 6));
    await tester.pumpAndSettle();
    final menu = find.byTooltip('管理设备');
    await tester.ensureVisible(menu);
    await tester.pumpAndSettle();
    await tester.tap(menu);
    await tester.pumpAndSettle();
    await tester.tap(find.text('批准此设备'));
    await tester.pumpAndSettle();
    expect(find.textContaining('不会自动上线'), findsOneWidget);
    await tester.tap(find.text('确认'));
    await tester.pumpAndSettle();
    expect(
      api.calls.where(
        (call) => call.contains('device-access/access-one/approve'),
      ),
      hasLength(1),
    );
    await tester.ensureVisible(find.text('房间设置'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('房间设置'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('新设备需要房主审批'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('新设备需要房主审批'));
    await tester.pumpAndSettle();
    expect(
      api.calls.where(
        (call) => call.contains('device-policy') && call.contains('true'),
      ),
      hasLength(1),
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('account leave confirmation explicitly covers every device', (
    tester,
  ) async {
    final api = await pump(tester, role: 'member', controls: true);
    await tester.tap(find.text('退出房间'));
    await tester.pumpAndSettle();
    expect(find.textContaining('此账号的所有设备都会退出'), findsOneWidget);
    await tester.tap(find.text('取消'));
    await tester.pumpAndSettle();
    expect(api.calls.where((call) => call.contains('/leave')), isEmpty);
  });

  testWidgets(
    'overview cards show people counts and open a separate detail view',
    (tester) async {
      await pump(tester, role: 'member', enterRoom: false);
      expect(find.text('1 / 2'), findsOneWidget);
      expect(find.text('房主 · 房主小林'), findsOneWidget);
      expect(find.text('连接后测量'), findsOneWidget);
      expect(find.textContaining('设备与连接'), findsNothing);
      expect(find.textContaining('user-'), findsNothing);
      await tester.tap(find.byKey(const ValueKey('room-card-$_roomId')));
      await tester.pumpAndSettle();
      expect(find.text('10.21.1.3'), findsOneWidget);
      await tester.tap(find.text('返回房间'));
      await tester.pumpAndSettle();
      expect(find.text('1 / 2'), findsOneWidget);
      expect(find.textContaining('设备与连接'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('room card measures owner RTT only from verified room peers', (
    tester,
  ) async {
    final api = await pump(
      tester,
      role: 'member',
      enterRoom: false,
      snapshot: _snapshot(),
    );
    expect(find.text('房主离线'), findsOneWidget);
    api.ownerOnline = true;
    await tester.pump(const Duration(seconds: 6));
    await tester.pumpAndSettle();
    expect(find.text('18 ms'), findsOneWidget);
    expect(find.text('3 ms'), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('offline device has a muted badge and no misleading latency', (
    tester,
  ) async {
    final api = await pump(tester, role: 'member');
    api.deviceOnline = false;
    await tester.pump(const Duration(seconds: 6));
    await tester.pumpAndSettle();
    expect(find.text('离线'), findsOneWidget);
    expect(find.text('未连接'), findsWidgets);
    expect(find.text('—'), findsOneWidget);
    expect(find.text('未测得'), findsNothing);
    final badge = tester.widget<Text>(find.text('离线'));
    final colors = Theme.of(tester.element(find.text('离线'))).colorScheme;
    expect(badge.style?.color, colors.onSurfaceVariant);
    await tester.ensureVisible(find.text('房间成员 · 2'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('房间成员 · 2'));
    await tester.pumpAndSettle();
    expect(find.byType(PopupMenuButton<bool>), findsNothing);
    expect(find.text('房主小林'), findsOneWidget);
    expect(find.textContaining('user-'), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'room device opens shared details with room-scoped live peer data',
    (tester) async {
      await pump(tester, role: 'member', snapshot: _snapshot());
      await tester.ensureVisible(
        find.byKey(const ValueKey('room-device-device-1')),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('room-device-device-1')));
      await tester.pumpAndSettle();
      expect(find.byType(Dialog), findsOneWidget);
      expect(find.text('设备详情'), findsOneWidget);
      expect(
        find.descendant(of: find.byType(Dialog), matching: find.text('18 ms')),
        findsWidgets,
      );
      expect(find.byKey(const Key('nodes-detail-close')), findsOneWidget);
      await tester.tap(find.byKey(const Key('nodes-detail-close')));
      await tester.pumpAndSettle();
      expect(find.byType(Dialog), findsNothing);
      expect(find.text('返回房间'), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'roster-only device details open without fabricated live measurements',
    (tester) async {
      await pump(tester, role: 'member');
      await tester.ensureVisible(
        find.byKey(const ValueKey('room-device-device-1')),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('room-device-device-1')));
      await tester.pumpAndSettle();
      expect(find.byType(Dialog), findsOneWidget);
      expect(find.textContaining('当前没有可用的实时链路信息'), findsOneWidget);
      expect(
        find.descendant(
          of: find.byType(Dialog),
          matching: find.text('10.21.1.3'),
        ),
        findsOneWidget,
      );
      expect(find.byType(PopupMenuButton<String>), findsNothing);
      await tester.tap(find.byKey(const Key('nodes-detail-close')));
      await tester.pumpAndSettle();
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'invitation opens canonical embedded room page without a second page',
    (tester) async {
      final invitation = RoomInvitation(
        'https://control.example',
        '12345678',
        List.filled(64, 'a').join(),
      ).toUri();
      await pump(tester, invitation: invitation, shell: true);
      expect(find.byType(RoomsPage), findsOneWidget);
      expect(tester.widget<RoomsPage>(find.byType(RoomsPage)).embedded, isTrue);
      expect(find.text('通过邀请链接加入'), findsOneWidget);
      await tester.tap(find.text('取消'));
      await tester.pumpAndSettle();
      final context = tester.element(find.byType(RoomsPage));
      expect(Navigator.of(context).canPop(), isFalse);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('joining from empty state lands in the same room detail', (
    tester,
  ) async {
    await pump(tester, empty: true, role: 'member');
    await tester.tap(find.text('加入房间'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const ValueKey('房间号')), '12345678');
    await tester.enterText(find.byKey(const ValueKey('房间密码')), 'password123');
    await tester.tap(find.text('确认'));
    await tester.pumpAndSettle();
    expect(find.text('朋友房间'), findsOneWidget);
    expect(find.text('设备与连接 · 1'), findsOneWidget);
    expect(find.byType(DropdownButtonFormField<String>), findsNothing);
    expect(
      Navigator.of(tester.element(find.byType(RoomsPage))).canPop(),
      isFalse,
    );
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'room peers show verified RTT and merge discovery without duplicate IPs',
    (tester) async {
      tester.view.physicalSize = const Size(800, 1100);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await pump(tester, role: 'member', snapshot: _snapshot());
      expect(find.text('10.21.1.3'), findsOneWidget);
      expect(find.text('10.21.1.4'), findsOneWidget);
      expect(find.text('18 ms'), findsOneWidget);
      expect(find.text('3 ms'), findsNothing);
      expect(find.text('直连'), findsOneWidget);
      expect(find.text('设备与连接 · 3'), findsOneWidget);
      expect(find.byTooltip('复制 IP'), findsNWidgets(3));
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('stale room catalog never displays live peer latency', (
    tester,
  ) async {
    await pump(tester, snapshot: _snapshot(stale: true));
    expect(find.text('18 ms'), findsNothing);
    expect(find.text('状态待更新'), findsNWidgets(2));
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('candidate RTT is not shown as a connected peer latency', (
    tester,
  ) async {
    await pump(tester, snapshot: _snapshot(verified: false));
    expect(find.text('18 ms'), findsNothing);
    expect(find.text('直连'), findsNothing);
    expect(find.text('建立连接中'), findsWidgets);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'owner management stays collapsed while device IP remains visible',
    (tester) async {
      tester.view.physicalSize = const Size(1200, 1800);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await pump(tester);
      expect(find.text('设备与连接 · 1'), findsOneWidget);
      expect(find.text('10.21.1.3'), findsOneWidget);
      expect(find.text('连接后测量'), findsOneWidget);
      expect(find.text('解散房间'), findsNothing);
      await tester.tap(find.text('房间设置'));
      await tester.pumpAndSettle();
      expect(find.text('解散房间'), findsOneWidget);
      await tester.tap(find.textContaining('成员管理 ·'));
      await tester.pumpAndSettle();
      expect(find.text('邀请管理'), findsOneWidget);
      expect(find.byType(PopupMenuButton<String>), findsOneWidget);
      expect(find.text('返回房间'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'members have no owner controls and compact layout has no overflow',
    (tester) async {
      tester.view.physicalSize = const Size(390, 900);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await pump(tester, role: 'member');
      expect(find.text('解散房间'), findsNothing);
      expect(find.text('邀请管理'), findsNothing);
      expect(find.byType(PopupMenuButton<String>), findsNothing);
      expect(find.text('退出房间'), findsOneWidget);
      expect(find.textContaining('成员管理 ·'), findsNothing);
      expect(find.text('房间成员 · 2'), findsOneWidget);
      expect(find.text('房间设置'), findsNothing);
      expect(
        tester.getTopLeft(find.text('退出房间')).dy,
        lessThan(tester.getTopLeft(find.text('设备与连接 · 1')).dy),
      );
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('create validates password and disposes the form after closing', (
    tester,
  ) async {
    final api = await pump(tester, empty: true);
    await tester.tap(find.text('创建房间'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const ValueKey('房间名称')), '一起玩');
    await tester.enterText(find.byKey(const ValueKey('房间密码')), 'short');
    await tester.tap(find.text('确认'));
    await tester.pumpAndSettle();
    expect(api.calls.where((call) => call.startsWith('create:')), isEmpty);
    expect(find.text('密码需为 8–72 字节'), findsOneWidget);
    await tester.enterText(find.byKey(const ValueKey('房间密码')), 'password123');
    await tester.tap(find.text('确认'));
    await tester.pumpAndSettle();
    expect(api.calls, contains('create:一起玩:password123'));
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'deep link never joins before confirmation and rejects other servers',
    (tester) async {
      final invitation = RoomInvitation(
        'https://evil.example',
        '12345678',
        List.filled(64, 'a').join(),
      ).toUri();
      final api = await pump(tester, invitation: invitation);
      expect(api.calls.where((call) => call.startsWith('join:')), isEmpty);
      await tester.tap(find.text('确认'));
      await tester.pumpAndSettle();
      expect(find.textContaining('邀请来自其他控制服务器'), findsOneWidget);
      expect(api.calls.where((call) => call.startsWith('join:')), isEmpty);
      await tester.tap(find.text('取消'));
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'room password join uses only the explicitly entered credentials',
    (tester) async {
      final api = await pump(tester, enterRoom: false);
      await tester.tap(find.text('加入房间'));
      await tester.pumpAndSettle();
      await tester.enterText(find.byKey(const ValueKey('房间号')), '87654321');
      await tester.enterText(find.byKey(const ValueKey('房间密码')), 'password456');
      await tester.tap(find.text('确认'));
      await tester.pumpAndSettle();
      expect(api.calls, contains('join:87654321:password456:null'));
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );
  testWidgets('operation errors survive successful background room refresh', (
    tester,
  ) async {
    final api = await pump(tester, enterRoom: false);
    api.joinError = '房间加入失败：房间密码不正确';
    await tester.tap(find.text('加入房间'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const ValueKey('房间号')), '87654321');
    await tester.enterText(find.byKey(const ValueKey('房间密码')), 'wrong-pass');
    await tester.tap(find.text('确认'));
    await tester.pumpAndSettle();
    expect(find.text(api.joinError!), findsOneWidget);
    await tester.pump(const Duration(seconds: 6));
    await tester.pumpAndSettle();
    expect(find.text(api.joinError!), findsOneWidget);
    await tester.tap(find.byTooltip('关闭提示'));
    await tester.pumpAndSettle();
    expect(find.text(api.joinError!), findsNothing);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('connection phase displays fine-grained status labels', (
    tester,
  ) async {
    // One confirmed Direct plus one unconfirmed online peer is only partial.
    final directSnap = _snapshot(verified: true);
    await pump(tester, snapshot: directSnap, enterRoom: false);
    await tester.pumpAndSettle();
    expect(find.text('部分连通'), findsWidgets);
    expect(find.text('已直连'), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());

    // 2. Waiting for peer
    final waitingSnap = DiagnosticsSnapshot.fromJson({
      'network_id': _roomId,
      'virtual_ip': '10.21.1.2',
      'node_id': 'local',
      'peers': <dynamic>[],
    });
    await pump(tester, snapshot: waitingSnap, enterRoom: false);
    await tester.pumpAndSettle();
    expect(find.text('等待好友'), findsWidgets);
    await tester.pumpWidget(const SizedBox.shrink());

    // 3. Handshaking
    final handshakingSnap = DiagnosticsSnapshot.fromJson({
      'network_id': _roomId,
      'virtual_ip': '10.21.1.2',
      'node_id': 'local',
      'peers': [
        {
          'node_id': 'remote',
          'device_name': '好友电脑',
          'virtual_ip': '10.21.1.3',
          'online': true,
          'state': 'handshake',
        },
      ],
    });
    await pump(tester, snapshot: handshakingSnap, enterRoom: false);
    await tester.pumpAndSettle();
    expect(find.text('建立加密会话'), findsWidgets);
    await tester.pumpWidget(const SizedBox.shrink());

    // 4. Relay confirmed
    final relaySnap = DiagnosticsSnapshot.fromJson({
      'network_id': _roomId,
      'virtual_ip': '10.21.1.2',
      'node_id': 'local',
      'peers': [
        {
          'node_id': 'remote',
          'device_name': '好友电脑',
          'virtual_ip': '10.21.1.3',
          'online': true,
          'active_path': 'relay',
          'state': 'relay',
          'relay_confirmed_endpoint': '1.2.3.4:443',
          'relay_confirmed_generation': 1,
        },
      ],
    });
    await pump(tester, snapshot: relaySnap, enterRoom: false);
    await tester.pumpAndSettle();
    expect(find.text('中继可用'), findsWidgets);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('review: unconfirmed relay is not shown as available', (
    tester,
  ) async {
    final snap = DiagnosticsSnapshot.fromJson({
      'network_id': _roomId,
      'virtual_ip': '10.21.1.2',
      'node_id': 'local',
      'peers': [
        {
          'node_id': 'remote',
          'online': true,
          'active_path': 'relay',
          'state': 'connecting',
        },
      ],
    });
    expect(snap.peers.single.isRelayVerified, isFalse);
    await pump(tester, snapshot: snap, enterRoom: false);
    final readyLabels = find.textContaining('中继可用').evaluate().length;
    await tester.pumpWidget(const SizedBox.shrink());
    expect(
      readyLabels,
      0,
      reason: 'An unconfirmed transport path is not an encrypted usable relay',
    );
  });

  testWidgets('review: transition polling reads daemon status within 600ms', (
    tester,
  ) async {
    _RoomRuntime.instances.clear();
    await pump(
      tester,
      snapshot: _snapshot(verified: false),
      enterRoom: false,
      enableDaemonPolling: true,
    );
    final runtime = _RoomRuntime.instances.last;
    final before = runtime.statusCalls;
    runtime.snapshot = _snapshot(verified: true);
    await tester.pump(const Duration(milliseconds: 600));
    await tester.pumpAndSettle();
    final after = runtime.statusCalls;
    await tester.pumpWidget(const SizedBox.shrink());
    expect(
      after,
      greaterThan(before),
      reason: '500ms adaptive polling must fetch a fresh daemon snapshot',
    );
  });
}
