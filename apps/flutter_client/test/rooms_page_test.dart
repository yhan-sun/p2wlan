import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:p2wlan_flutter_client/app/navigation.dart';
import 'package:p2wlan_flutter_client/app/p2wlan_colors.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/rooms/parallel_rooms.dart';
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/capabilities/platform_capabilities.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/rooms/room_api.dart';
import 'package:p2wlan_flutter_client/core/rooms/room_profiles.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';
import 'package:p2wlan_flutter_client/features/rooms/rooms_page.dart';

final _token =
    'a.${base64Url.encode(utf8.encode(jsonEncode({'user_id': 'member'})))}.b';

const _roomId = 'room-0123456789abcdef0123456789abcdef';
const _expired = RoomException('登录状态已失效，请重新登录', code: 'auth_expired');
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
  String? listError;
  RoomException? listException;
  RoomException? rosterException;
  RoomException? inviteException;
  RoomException? joinException;
  RoomException? mutationException;
  Completer<Map<String, dynamic>>? pendingMutation;
  final bannedUserIds = <String>[];
  Completer<Map<String, dynamic>>? pendingDeviceAction;
  Completer<Map<String, dynamic>>? pendingInvite;
  Completer<FriendRoom>? pendingJoin;
  Completer<List<FriendRoom>>? pendingList;
  bool summaries = false;
  String? rosterError;
  String? inviteError;
  int rosterCalls = 0;
  final calls = <String>[];
  int listCalls = 0;
  @override
  Future<List<FriendRoom>> list() async {
    listCalls++;
    if (pendingList != null) return pendingList!.future;
    if (listException != null) throw listException!;
    if (listError != null) throw RoomException(listError!);
    userId = role == 'owner' ? 'owner' : 'member';
    return empty
        ? []
        : [
            FriendRoom.fromJson({
              ..._room(role),
              if (summaries) ...{
                'member_count': 2,
                'online_member_count': 1,
                'owner_device_ips': ['10.21.1.3'],
              },
              if (controls) 'device_controls_version': 1,
            }),
          ];
  }

  @override
  Future<RoomRoster> roster(String room) async {
    rosterCalls++;
    if (rosterException != null) throw rosterException!;
    if (rosterError != null) throw RoomException(rosterError!);
    return RoomRoster.fromJson({
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
      'banned_user_ids': bannedUserIds,
    });
  }

  @override
  Future<Map<String, dynamic>> request(
    String method,
    List<String> segments, [
    Map<String, dynamic>? payload,
  ]) async {
    calls.add('$method ${segments.join('/')} ${jsonEncode(payload)}');
    if (method != 'GET' && pendingMutation != null) {
      return pendingMutation!.future;
    }
    if (method != 'GET' && mutationException != null) throw mutationException!;
    if (method == 'DELETE' && segments.contains('bans')) {
      bannedUserIds.remove(segments.last);
    }
    if (method == 'POST' && segments.contains('device-access')) {
      if (pendingDeviceAction != null) return pendingDeviceAction!.future;
      accessState = segments.last == 'block' ? 'blocked' : 'paused';
    }
    if (method == 'PUT' && segments.last == 'device-policy') {
      approvalRequired = payload?['require_approval'] == true;
    }
    if (method == 'POST' &&
        segments.last == 'invites' &&
        pendingInvite != null) {
      return pendingInvite!.future;
    }
    if (method == 'GET' && segments.last == 'invites') {
      if (inviteException != null) throw inviteException!;
      if (inviteError != null) throw RoomException(inviteError!);
      return {'invites': []};
    }
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
    if (pendingJoin != null) return pendingJoin!.future;
    if (joinException != null) throw joinException!;
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
    super.daemonController,
    super.enableFreshnessTimer = false,
  });
  void pulse() => notifyListeners();
}

class _RoomDiagnostics extends DiagnosticsApi {
  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => false;
}

class _RoomDaemon extends DaemonController {
  _RoomDaemon(DiagnosticsApi api, {this.localIdentity = false})
    : super(diagnosticsApi: api);
  final bool localIdentity;
  int stopCalls = 0;
  Completer<DaemonCommandResult>? pendingStop;
  @override
  Future<Map<String, String>?> roomDeviceIdentity(AppSettings settings) async =>
      localIdentity ? {'node_id': 'device-1', 'public_key': 'key-one'} : null;
  @override
  Future<DaemonCommandResult> stop(String diagnosticsUrl) async {
    stopCalls++;
    if (pendingStop != null) return pendingStop!.future;
    return const DaemonCommandResult(ok: true, message: '', graceful: true);
  }
}

class _RoomRuntime implements RoomRuntime {
  _RoomRuntime(this.snapshot) {
    instances.add(this);
  }
  static final instances = <_RoomRuntime>[];
  DiagnosticsSnapshot snapshot;
  int statusCalls = 0;
  int startCalls = 0;
  int stopCalls = 0;
  static Completer<void>? pendingStart;
  @override
  Future<bool> exists() async => false;
  @override
  Future<DaemonCommandResult> start() async {
    startCalls++;
    await pendingStart?.future;
    return const DaemonCommandResult(ok: true, message: '');
  }

  @override
  Future<DaemonCommandResult> stop() async {
    stopCalls++;
    return const DaemonCommandResult(ok: true, message: '');
  }

  @override
  Future<DiagnosticsSnapshot> status() async {
    statusCalls++;
    return snapshot;
  }

  @override
  void close() {}
}

DiagnosticsSnapshot _snapshot({
  bool stale = false,
  bool verified = true,
  bool capturedMismatch = false,
}) => DiagnosticsSnapshot.fromJson({
  'network_id': _roomId,
  'virtual_ip': '10.21.1.2',
  'node_id': 'local',
  'peer_snapshot_stale': stale,
  'revision': 8,
  'captured_revision': capturedMismatch ? 7 : 8,
  'peers': [
    {
      'node_id': 'device-1',
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
    bool settleInitial = true,
    VoidCallback? onReauthenticate,
    bool enableDaemonPolling = false,
    bool controls = false,
    bool canConnect = false,
    bool localIdentity = false,
    bool primaryRoom = false,
    void Function(
      SettingsStore,
      _PulsingStatusStore,
      _RoomDaemon,
      ParallelRooms,
    )?
    onStores,
    double textScale = 1,
    void Function(_FakeRoomApi)? configureApi,
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
          deviceName: '本机电脑',
          networkId: primaryRoom ? _roomId : defaultNetworkId,
          overlayCidr: primaryRoom ? '10.21.1.0/24' : defaultOverlayCidr,
        ),
      );
      if (primaryRoom) {
        await settings.updateSettings(
          selectRoomSettings(
            settings.settings,
            FriendRoom.fromJson(_room(role)),
          ),
        );
      }
    });
    final parallel = ParallelRooms(
      readSettings: () => settings.settings,
      supported: snapshot != null || canConnect,
      refreshInterval: enableDaemonPolling
          ? const Duration(seconds: 5)
          : Duration.zero,
      runtimeFactory: (_) => _RoomRuntime(
        snapshot ??
            DiagnosticsSnapshot.fromJson({
              'network_id': _roomId,
              'node_id': 'local',
              'virtual_ip': '10.21.1.2',
              'peers': [],
            }),
      ),
    );
    if (snapshot != null) {
      await parallel.connect(FriendRoom.fromJson(_room(role)));
    }
    final diagnostics = _RoomDiagnostics();
    final daemon = _RoomDaemon(diagnostics, localIdentity: localIdentity);
    final status = _PulsingStatusStore(
      parallelRooms: parallel,
      settingsStore: settings,
      diagnosticsApi: diagnostics,
      daemonController: daemon,
      enableFreshnessTimer: false,
    );
    onStores?.call(settings, status, daemon, parallel);
    onStatusPulse?.call(status.pulse);
    final api = _FakeRoomApi(role: role, empty: empty, controls: controls);
    configureApi?.call(api);
    addTearDown(() {
      api.close();
      status.dispose();
      settings.dispose();
      dir.deleteSync(recursive: true);
    });
    await tester.pumpWidget(
      MaterialApp(
        builder: (context, child) => MediaQuery(
          data: MediaQuery.of(context)
              .copyWith(textScaler: TextScaler.linear(textScale)),
          child: child!,
        ),
        home: shell
            ? P2WlanShell(
                settingsStore: settings,
                statusStore: status,
                roomInvitation: invitation,
                capabilities: PlatformCapabilities.fromPlatform(
                  canConnect ? 'linux' : 'ios',
                ),
              )
            : RoomsPage(
                settingsStore: settings,
                statusStore: status,
                api: api,
                onReauthenticate: onReauthenticate,
                capabilities: PlatformCapabilities.fromPlatform(
                  canConnect ? 'linux' : 'ios',
                ),
                initialInvitation: invitation,
              ),
      ),
    );
    if (settleInitial) await tester.pumpAndSettle();
    if (enterRoom && !empty && invitation == null && !shell && !primaryRoom) {
      await tester.tap(find.byKey(const ValueKey('room-card-$_roomId')));
      await tester.pumpAndSettle();
    }
    return api;
  }

  testWidgets(
    'expired room login pauses polling, keeps context and permits local disconnect',
    (tester) async {
      var reauthenticationCalls = 0;
      late VoidCallback statusPulse;
      late ParallelRooms parallel;
      final api = await pump(
        tester,
        canConnect: true,
        snapshot: _snapshot(),
        onReauthenticate: () => reauthenticationCalls++,
        onStatusPulse: (pulse) => statusPulse = pulse,
        onStores: (_, _, _, rooms) => parallel = rooms,
      );
      api.listException = _expired;
      await tester.tap(find.byTooltip('刷新房间'));
      await tester.pumpAndSettle();
      expect(find.textContaining('自动刷新已暂停'), findsOneWidget);
      expect(find.text('10.21.1.3'), findsOneWidget);
      expect(find.byKey(const ValueKey('retry-room-roster')), findsOneWidget);
      final callsAfterFailure = api.listCalls;
      statusPulse();
      await tester.pump(const Duration(seconds: 30));
      await tester.pumpAndSettle();
      expect(api.listCalls, callsAfterFailure);
      await tester.ensureVisible(find.text('重新登录'));
      await tester.tap(find.text('重新登录'));
      expect(reauthenticationCalls, 1);
      final connection = find.byKey(
        const ValueKey('room-detail-connection-$_roomId'),
      );
      await tester.ensureVisible(connection);
      await tester.pumpAndSettle();
      expect(tester.widget<FilledButton>(connection).onPressed, isNotNull);
      await tester.tap(connection);
      await tester.pumpAndSettle();
      expect(parallel.session(_roomId), isNull);
      expect(api.listCalls, callsAfterFailure);
      expect(tester.widget<FilledButton>(connection).onPressed, isNull);
      api.listException = null;
      await tester.ensureVisible(find.text('重试验证登录'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('重试验证登录'));
      await tester.pumpAndSettle();
      expect(find.text('重新登录'), findsNothing);
      final callsAfterRecovery = api.listCalls;
      expect(callsAfterRecovery, callsAfterFailure + 1);
      await tester.pump(const Duration(seconds: 6));
      await tester.pumpAndSettle();
      expect(api.listCalls, greaterThan(callsAfterRecovery));
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('an older refresh cannot clear a newer authentication failure', (
    tester,
  ) async {
    final api = await pump(tester, onReauthenticate: () {});
    final mutation = Completer<Map<String, dynamic>>();
    api.pendingMutation = mutation;
    await tester.ensureVisible(find.text('房间设置'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('房间设置'));
    await tester.pumpAndSettle();
    await tester.ensureVisible(find.text('锁定新成员加入'));
    await tester.tap(find.text('锁定新成员加入'));
    await tester.pump();
    final oldList = Completer<List<FriendRoom>>();
    api.pendingList = oldList;
    // Pull-to-refresh can start while a server mutation is pending. Its view
    // generation is newer, but its authentication evidence is still older.
    final refresh = tester
        .widget<RefreshIndicator>(find.byType(RefreshIndicator))
        .onRefresh();
    await tester.pump();
    mutation.completeError(_expired);
    await tester.pumpAndSettle();
    expect(find.text('重新登录'), findsOneWidget);
    api.pendingList = null;
    oldList.complete([FriendRoom.fromJson(_room('owner'))]);
    await refresh;
    await tester.pumpAndSettle();
    expect(find.text('重新登录'), findsOneWidget);
    expect(find.byKey(const ValueKey('retry-room-roster')), findsOneWidget);
    final calls = api.listCalls;
    await tester.pump(const Duration(seconds: 15));
    await tester.pumpAndSettle();
    expect(api.listCalls, calls);
    api.rosterError = '成员信息仍暂不可用';
    await tester.ensureVisible(find.text('重试验证登录'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('重试验证登录'));
    await tester.pumpAndSettle();
    expect(find.text('重新登录'), findsOneWidget);
    api.rosterError = null;
    api.inviteError = '邀请信息仍暂不可用';
    await tester.ensureVisible(find.text('重试验证登录'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('重试验证登录'));
    await tester.pumpAndSettle();
    expect(find.text('重新登录'), findsOneWidget);
    api.inviteError = null;
    await tester.ensureVisible(find.text('重试验证登录'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('重试验证登录'));
    await tester.pumpAndSettle();
    expect(find.text('重新登录'), findsNothing);
    final recoveredCalls = api.listCalls;
    await tester.pump(const Duration(seconds: 6));
    await tester.pumpAndSettle();
    expect(api.listCalls, greaterThan(recoveredCalls));
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  for (final source in ['roster', 'invites']) {
    testWidgets(
      '$source authentication failure offers login and pauses automatic retries',
      (tester) async {
        final api = await pump(
          tester,
          enterRoom: source != 'roster',
          onReauthenticate: () {},
          configureApi: (api) {
            if (source == 'roster') {
              api.rosterException = _expired;
            } else {
              api.inviteException = _expired;
            }
          },
        );
        expect(find.text('重新登录'), findsOneWidget);
        expect(find.text('和好友连接到同一房间'), findsNothing);
        expect(find.textContaining('尚未生成邀请'), findsNothing);
        final calls = api.listCalls;
        await tester.pump(const Duration(seconds: 15));
        await tester.pumpAndSettle();
        expect(api.listCalls, calls);
        expect(tester.takeException(), isNull);
        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  }

  testWidgets(
    'join authentication failure closes its form and offers the shared recovery action',
    (tester) async {
      final api = await pump(tester, empty: true, onReauthenticate: () {});
      api.joinException = _expired;
      await tester.tap(find.text('加入房间'));
      await tester.pumpAndSettle();
      await tester.enterText(find.byKey(const ValueKey('房间号')), '12345678');
      await tester.enterText(find.byKey(const ValueKey('房间密码')), 'password123');
      await tester.tap(find.text('确认'));
      await tester.pumpAndSettle();
      expect(find.byType(AlertDialog), findsNothing);
      expect(find.text('重新登录'), findsOneWidget);
      expect(find.text('返回房间'), findsNothing);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'server mutation authentication failure is kept as a recovery state',
    (tester) async {
      final api = await pump(tester, onReauthenticate: () {});
      api.mutationException = _expired;
      await tester.ensureVisible(find.text('房间设置'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('房间设置'));
      await tester.pumpAndSettle();
      await tester.ensureVisible(find.text('锁定新成员加入'));
      await tester.tap(find.text('锁定新成员加入'));
      await tester.pumpAndSettle();
      expect(find.text('重新登录'), findsOneWidget);
      final calls = api.listCalls;
      await tester.pump(const Duration(seconds: 15));
      await tester.pumpAndSettle();
      expect(api.listCalls, calls);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'banned accounts use full unique IDs and repeat the chosen target before unbanning',
    (tester) async {
      tester.view.physicalSize = const Size(360, 1000);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      const first = 'account-shared-prefix-00000000-aaaaaaaa';
      const second = 'account-shared-prefix-00000000-bbbbbbbb';
      final api = await pump(
        tester,
        textScale: 2,
        configureApi: (api) => api.bannedUserIds.addAll([first, second]),
      );
      await tester.ensureVisible(find.text('邀请管理'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('邀请管理'));
      await tester.pumpAndSettle();
      expect(find.text(first), findsOneWidget);
      expect(find.text(second), findsOneWidget);
      final action = find.byTooltip('解除账号 $second 的封禁');
      expect(tester.getSize(find.text(second)).width, greaterThan(260));
      expect(
        tester.getTopLeft(action).dy,
        greaterThan(tester.getBottomLeft(find.text(second)).dy),
      );
      await tester.ensureVisible(action);
      await tester.pumpAndSettle();
      await tester.tap(action);
      await tester.pumpAndSettle();
      expect(find.textContaining('解除账号 $second 的封禁后'), findsOneWidget);
      expect(find.textContaining('解除账号 $first 的封禁后'), findsNothing);
      await tester.tap(find.text('确认'));
      await tester.pumpAndSettle();
      expect(
        api.calls.where((call) => call.startsWith('DELETE $_roomId/bans/')),
        ['DELETE $_roomId/bans/$second null'],
      );
      expect(api.bannedUserIds, [first]);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  for (final restoreToken in [false, true]) {
    testWidgets(
      'late authentication failure cannot pause another session (restore token: $restoreToken)',
      (tester) async {
        late SettingsStore settings;
        final api = await pump(
          tester,
          enterRoom: false,
          onReauthenticate: () {},
          onStores: (store, _, _, _) => settings = store,
        );
        final pending = Completer<List<FriendRoom>>();
        api.pendingList = pending;
        await tester.tap(find.byTooltip('刷新房间'));
        await tester.pump();
        await tester.runAsync(() async {
          await settings.updateSettings(
            settings.settings.copyWith(authToken: '${_token}new'),
          );
          if (restoreToken) {
            await settings.updateSettings(
              settings.settings.copyWith(authToken: _token),
            );
          }
        });
        api.pendingList = null;
        pending.completeError(_expired);
        await tester.pumpAndSettle();
        expect(find.text('重新登录'), findsNothing);
        expect(find.textContaining('自动刷新已暂停'), findsNothing);
        if (restoreToken) {
          final calls = api.listCalls;
          await tester.pump(const Duration(seconds: 6));
          await tester.pumpAndSettle();
          expect(api.listCalls, greaterThan(calls));
        }
        expect(tester.takeException(), isNull);
        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  }

  testWidgets(
    'authentication wording without its typed code does not stop polling',
    (tester) async {
      final api = await pump(tester, enterRoom: false, onReauthenticate: () {});
      api.listError = _expired.message;
      await tester.tap(find.byTooltip('刷新房间'));
      await tester.pumpAndSettle();
      expect(find.text('重新登录'), findsNothing);
      final calls = api.listCalls;
      await tester.pump(const Duration(seconds: 6));
      await tester.pumpAndSettle();
      expect(api.listCalls, greaterThan(calls));
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('creation waits until initial ownership is known', (
    tester,
  ) async {
    final pending = Completer<List<FriendRoom>>();
    await pump(
      tester,
      empty: true,
      enterRoom: false,
      settleInitial: false,
      configureApi: (api) => api.pendingList = pending,
    );
    final create = find.widgetWithText(FilledButton, '创建房间');
    expect(tester.widget<FilledButton>(create).onPressed, isNull);
    expect(
      tester
          .widget<LinearProgressIndicator>(find.byType(LinearProgressIndicator))
          .semanticsLabel,
      '正在加载房间',
    );
    pending.complete([]);
    await tester.pumpAndSettle();
    expect(tester.widget<FilledButton>(create).onPressed, isNotNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('password visibility preserves the entered join credential', (
    tester,
  ) async {
    final api = await pump(tester, empty: true);
    await tester.tap(find.text('加入房间'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const ValueKey('房间号')), '12345678');
    await tester.enterText(find.byKey(const ValueKey('房间密码')), 'password123');
    final field = find.descendant(
      of: find.byKey(const ValueKey('房间密码')),
      matching: find.byType(TextField),
    );
    expect(tester.widget<TextField>(field).obscureText, isTrue);
    await tester.tap(find.byTooltip('显示房间密码'));
    await tester.pumpAndSettle();
    expect(tester.widget<TextField>(field).obscureText, isFalse);
    expect(tester.widget<TextField>(field).controller!.text, 'password123');
    expect(find.byTooltip('隐藏房间密码'), findsOneWidget);
    await tester.tap(find.text('确认'));
    await tester.pumpAndSettle();
    expect(api.calls, contains('join:12345678:password123:null'));
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('incomplete snapshot revisions hide live room paths and RTT', (
    tester,
  ) async {
    await pump(tester, snapshot: _snapshot(capturedMismatch: true));
    expect(find.text('18 ms'), findsNothing);
    expect(find.text('直连'), findsNothing);
    expect(find.text('状态待更新'), findsNWidgets(3));
    expect(find.text('链路 / 数据'), findsOneWidget);
    await tester.ensureVisible(
      find.byKey(const ValueKey('room-device-device-1')),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const ValueKey('room-device-device-1')));
    await tester.pumpAndSettle();
    expect(find.text('18 ms'), findsNothing);
    expect(find.textContaining('房间数据：状态待更新'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('summary without roster explains unavailable owner latency', (
    tester,
  ) async {
    await pump(
      tester,
      role: 'member',
      enterRoom: false,
      snapshot: _snapshot(),
      configureApi: (api) => api.summaries = true,
    );
    expect(find.text('进入房间后查看'), findsOneWidget);
    expect(find.text('未测得'), findsNothing);
    expect(find.text('18 ms'), findsNothing);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  for (final lateCopy in [false, true]) {
    testWidgets(
      'invitation copy handles ${lateCopy ? 'a newer modal' : 'clipboard failure'}',
      (tester) async {
        final copied = Completer<Object?>();
        TestDefaultBinaryMessengerBinding.instance.defaultBinaryMessenger
            .setMockMethodCallHandler(SystemChannels.platform, (call) async {
              if (call.method == 'Clipboard.setData') {
                if (lateCopy) return copied.future;
                throw PlatformException(code: 'clipboard_unavailable');
              }
              return null;
            });
        addTearDown(
          () => TestDefaultBinaryMessengerBinding
              .instance
              .defaultBinaryMessenger
              .setMockMethodCallHandler(SystemChannels.platform, null),
        );
        final api = await pump(tester);
        final invite = Completer<Map<String, dynamic>>();
        api.pendingInvite = invite;
        await tester.tap(find.text('生成邀请'));
        await tester.pumpAndSettle();
        await tester.tap(find.text('确认'));
        await tester.pump();
        invite.complete({'invite_token': 'a' * 64});
        await tester.pump();
        await tester.pump(const Duration(milliseconds: 300));
        expect(find.text('分享房间'), findsOneWidget);
        await tester.tap(find.text('复制邀请链接'));
        await tester.pump();
        if (lateCopy) {
          final navigator = Navigator.of(tester.element(find.text('分享房间')));
          unawaited(
            navigator.push<void>(
              MaterialPageRoute(
                builder: (_) => const Scaffold(body: Text('新页面仍保留')),
              ),
            ),
          );
          await tester.pump();
          await tester.pump(const Duration(milliseconds: 300));
          copied.complete(null);
          await tester.pump();
          expect(find.text('新页面仍保留'), findsOneWidget);
          navigator.pop();
          await tester.pump();
          await tester.pump(const Duration(milliseconds: 300));
        } else {
          expect(find.text('复制失败，请手动选择并复制'), findsOneWidget);
        }
        expect(find.text('分享房间'), findsOneWidget);
        expect(tester.takeException(), isNull);
        Navigator.of(tester.element(find.byType(RoomsPage)))
            .popUntil((route) => route.isFirst);
        await tester.pumpAndSettle();
        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  }

  testWidgets(
    'medium room cards and device rows keep compact readable spacing',
    (tester) async {
      tester.view.physicalSize = const Size(604, 900);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await pump(tester, enterRoom: false, canConnect: true);
      expect(
        tester.getSize(find.byKey(const ValueKey('room-card-$_roomId'))).height,
        lessThanOrEqualTo(175),
      );
      expect(find.text('我是房主'), findsNothing);
      await tester.tap(find.byKey(const ValueKey('room-card-$_roomId')));
      await tester.pumpAndSettle();
      expect(
        tester
            .getSize(find.byKey(const ValueKey('room-device-device-1')))
            .height,
        lessThanOrEqualTo(120),
      );
      expect(find.text('10.21.1.3'), findsOneWidget);
      expect(
        tester
            .getTopLeft(find.byKey(const ValueKey('room-device-device-1')))
            .dy,
        lessThan(tester.getTopLeft(find.text('我 · 房主 · 0 台设备')).dy),
      );
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('two room cards share the available desktop width', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    const secondId = 'room-1123456789abcdef0123456789abcdef';
    await pump(
      tester,
      enterRoom: false,
      configureApi: (api) =>
          api.pendingList = Completer<List<FriendRoom>>()
            ..complete([
              for (final id in [_roomId, secondId])
                FriendRoom.fromJson({
                  ..._room('member'),
                  'id': id,
                  'member_count': 2,
                  'online_member_count': 1,
                }),
            ]),
    );
    final first = find.byKey(const ValueKey('room-card-$_roomId'));
    final second = find.byKey(const ValueKey('room-card-$secondId'));
    expect(tester.getSize(first).width, greaterThan(580));
    expect(tester.getSize(first).width, tester.getSize(second).width);
    expect(tester.getTopLeft(first).dy, tester.getTopLeft(second).dy);
    expect(tester.getTopRight(second).dx, closeTo(1252, 1));
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  for (final restoreToken in [false, true]) {
    testWidgets(
      'old device response cannot disconnect a replacement session (restore token: $restoreToken)',
      (tester) async {
        late SettingsStore settings;
        late ParallelRooms parallel;
        final api = await pump(
          tester,
          role: 'member',
          controls: true,
          canConnect: true,
          localIdentity: true,
          snapshot: _snapshot(),
          onStores: (store, _, _, rooms) {
            settings = store;
            parallel = rooms;
          },
        );
        final response = Completer<Map<String, dynamic>>();
        api.pendingDeviceAction = response;
        await tester.ensureVisible(find.byTooltip('管理设备'));
        await tester.pumpAndSettle();
        await tester.tap(find.byTooltip('管理设备'));
        await tester.pumpAndSettle();
        await tester.tap(find.text('断开此设备'));
        await tester.pumpAndSettle();
        await tester.tap(find.text('确认'));
        await tester.pump();
        expect(
          api.calls.where(
            (call) => call.contains('device-access/access-one/disconnect'),
          ),
          hasLength(1),
        );
        await tester.runAsync(() async {
          await settings.updateSettings(
            settings.settings.copyWith(authToken: '${_token}new'),
          );
          if (restoreToken) {
            await settings.updateSettings(
              settings.settings.copyWith(authToken: _token),
            );
          }
          await parallel.stopAll();
          final connected = await parallel.connect(
            FriendRoom.fromJson(_room('member')),
          );
          expect(connected.ok, isTrue, reason: connected.message);
        });
        final replacement = parallel.session(_roomId)!;
        final runtime = replacement.runtime as _RoomRuntime;
        response.complete({'success': true});
        await tester.pumpAndSettle();
        expect(identical(parallel.session(_roomId), replacement), isTrue);
        expect(runtime.stopCalls, 0);
        expect(
          (await parallel.connectionPreference(replacement.plan.room)).wanted,
          isTrue,
        );
        expect(find.text('断开此设备：已完成'), findsNothing);
        expect(tester.takeException(), isNull);
        await tester.pumpWidget(const SizedBox.shrink());
      },
    );
  }

  testWidgets(
    'old primary-stop completion cannot reset a replacement room configuration',
    (tester) async {
      late SettingsStore settings;
      late _RoomDaemon daemon;
      late ParallelRooms parallel;
      await pump(
        tester,
        primaryRoom: true,
        canConnect: true,
        onStores: (store, _, controller, rooms) {
          settings = store;
          daemon = controller;
          parallel = rooms;
        },
      );
      final stopped = Completer<DaemonCommandResult>();
      daemon.pendingStop = stopped;
      await tester.tap(
        find.byKey(const ValueKey('room-detail-connection-$_roomId')),
      );
      await tester.pump();
      expect(daemon.stopCalls, 1);
      // Model an externally replaced session while an old platform call is pending.
      settings.applySessionChange = null;
      await tester.runAsync(() async {
        await settings.updateSettings(
          settings.settings.copyWith(authToken: '${_token}new'),
        );
        await settings.updateSettings(
          selectRoomSettings(
            settings.settings,
            FriendRoom.fromJson(_room('member')),
          ),
        );
      });
      stopped.complete(const DaemonCommandResult(ok: true, message: ''));
      await tester.pumpAndSettle();
      expect(settings.settings.networkId, _roomId);
      expect(settings.settings.authToken, '${_token}new');
      expect(parallel.session(_roomId), isNull);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'old invite response never opens credentials in a replacement account',
    (tester) async {
      late SettingsStore settings;
      final api = await pump(
        tester,
        onStores: (store, _, _, _) => settings = store,
      );
      final response = Completer<Map<String, dynamic>>();
      api.pendingInvite = response;
      await tester.tap(find.text('生成邀请'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('确认'));
      await tester.pump();
      await tester.runAsync(
        () => settings.updateSettings(
          settings.settings.copyWith(authToken: '${_token}new'),
        ),
      );
      response.complete({'invite_token': 'a' * 64});
      await tester.pumpAndSettle();
      expect(find.text('分享房间'), findsNothing);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  for (final restoreToken in [false, true]) {
    for (final fail in [false, true]) {
      testWidgets(
        'old join ${fail ? 'error' : 'success'} is ignored after session replacement (restore token: $restoreToken)',
        (tester) async {
          late SettingsStore settings;
          final api = await pump(
            tester,
            empty: true,
            onStores: (store, _, _, _) => settings = store,
          );
          final response = Completer<FriendRoom>();
          api.pendingJoin = response;
          await tester.tap(find.text('加入房间'));
          await tester.pumpAndSettle();
          await tester.enterText(find.byKey(const ValueKey('房间号')), '12345678');
          await tester.enterText(
            find.byKey(const ValueKey('房间密码')),
            'password123',
          );
          await tester.tap(find.text('确认'));
          await tester.pump();
          expect(find.text('正在加入…'), findsOneWidget);
          await tester.runAsync(() async {
            await settings.updateSettings(
              settings.settings.copyWith(authToken: '${_token}new'),
            );
            if (restoreToken) {
              await settings.updateSettings(
                settings.settings.copyWith(authToken: _token),
              );
            }
          });
          if (fail) {
            response.completeError(const RoomException('旧账号请求失败'));
          } else {
            response.complete(FriendRoom.fromJson(_room('member')));
          }
          await tester.pumpAndSettle();
          expect(find.byType(AlertDialog), findsNothing);
          expect(find.text('返回房间'), findsNothing);
          expect(find.text('旧账号请求失败'), findsNothing);
          expect(find.textContaining('账号已加入房间'), findsNothing);
          expect(tester.takeException(), isNull);
          await tester.pumpWidget(const SizedBox.shrink());
        },
      );
    }
  }

  testWidgets(
    'pending join prevents duplicate submissions and accidental dismissals',
    (tester) async {
      final api = await pump(tester, empty: true);
      final response = Completer<FriendRoom>();
      api.pendingJoin = response;
      await tester.tap(find.text('加入房间'));
      await tester.pumpAndSettle();
      await tester.enterText(find.byKey(const ValueKey('房间号')), '12345678');
      await tester.enterText(find.byKey(const ValueKey('房间密码')), 'password123');
      final confirm = tester
          .widget<FilledButton>(find.widgetWithText(FilledButton, '确认'))
          .onPressed!;
      confirm();
      confirm();
      await tester.pump();
      expect(api.calls.where((call) => call.startsWith('join:')), hasLength(1));
      expect(
        tester
            .widget<FilledButton>(find.widgetWithText(FilledButton, '正在加入…'))
            .onPressed,
        isNull,
      );
      expect(
        tester
            .widget<TextButton>(find.widgetWithText(TextButton, '取消'))
            .onPressed,
        isNull,
      );
      expect(
        tester.widget<TextFormField>(find.byKey(const ValueKey('房间号'))).enabled,
        isFalse,
      );
      expect(
        tester
            .widget<TextFormField>(find.byKey(const ValueKey('房间密码')))
            .enabled,
        isFalse,
      );
      expect(
        tester
            .widget<CircularProgressIndicator>(
              find.byType(CircularProgressIndicator),
            )
            .semanticsLabel,
        '正在加入房间',
      );
      expect(
        await Navigator.of(tester.element(find.byType(AlertDialog))).maybePop(),
        isTrue,
      );
      await tester.pump();
      expect(find.byType(AlertDialog), findsOneWidget);
      api.empty = false;
      response.complete(FriendRoom.fromJson(_room('member')));
      await tester.pumpAndSettle();
      expect(find.byType(AlertDialog), findsNothing);
      expect(find.text('返回房间'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('late join completion after form disposal performs no UI write', (
    tester,
  ) async {
    final api = await pump(tester, empty: true);
    final response = Completer<FriendRoom>();
    api.pendingJoin = response;
    await tester.tap(find.text('加入房间'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const ValueKey('房间号')), '12345678');
    await tester.enterText(find.byKey(const ValueKey('房间密码')), 'password123');
    await tester.tap(find.text('确认'));
    await tester.pump();
    await tester.pumpWidget(
      const MaterialApp(home: Scaffold(body: Text('新的页面'))),
    );
    response.completeError(const RoomException('旧页面请求失败'));
    await tester.pumpAndSettle();
    expect(find.text('新的页面'), findsOneWidget);
    expect(find.text('旧页面请求失败'), findsNothing);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('stale join only closes its own form beneath a newer route', (
    tester,
  ) async {
    late SettingsStore settings;
    final api = await pump(
      tester,
      empty: true,
      onStores: (store, _, _, _) => settings = store,
    );
    final response = Completer<FriendRoom>();
    api.pendingJoin = response;
    await tester.tap(find.text('加入房间'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const ValueKey('房间号')), '12345678');
    await tester.enterText(find.byKey(const ValueKey('房间密码')), 'password123');
    await tester.tap(find.text('确认'));
    await tester.pump();
    final navigator = Navigator.of(tester.element(find.byType(AlertDialog)));
    unawaited(
      navigator.push<void>(
        MaterialPageRoute(builder: (_) => const Scaffold(body: Text('正在重新登录'))),
      ),
    );
    await tester.pump();
    await tester.runAsync(
      () => settings.updateSettings(
        settings.settings.copyWith(authToken: '${_token}new'),
      ),
    );
    response.completeError(const RoomException('旧账号请求失败'));
    await tester.pumpAndSettle();
    expect(find.text('正在重新登录'), findsOneWidget);
    expect(find.text('旧账号请求失败'), findsNothing);
    navigator.pop();
    await tester.pumpAndSettle();
    expect(find.byType(AlertDialog), findsNothing);
    expect(find.text('返回房间'), findsNothing);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('failed invitation remains editable for a replacement link', (
    tester,
  ) async {
    final api = await pump(tester, enterRoom: false);
    api.joinError = '邀请已失效，请向房主索取新链接';
    String link(String token) =>
        'p2wlan://join?server=https%3A%2F%2Fcontrol.example&room=87654321#invite=$token';
    await tester.tap(find.text('加入房间'));
    await tester.pumpAndSettle();
    await tester.enterText(find.byKey(const ValueKey('房间号')), link('a' * 64));
    await tester.pumpAndSettle();
    await tester.tap(find.text('确认'));
    await tester.pumpAndSettle();
    expect(
      find.descendant(
        of: find.byType(AlertDialog),
        matching: find.text(api.joinError!),
      ),
      findsOneWidget,
    );
    expect(find.byKey(const ValueKey('房间密码')), findsNothing);
    expect(
      tester
          .widget<TextField>(
            find.descendant(
              of: find.byKey(const ValueKey('房间号')),
              matching: find.byType(TextField),
            ),
          )
          .controller!
          .text,
      link('a' * 64),
    );
    api.joinError = null;
    await tester.enterText(find.byKey(const ValueKey('房间号')), link('b' * 64));
    await tester.pumpAndSettle();
    await tester.tap(find.text('确认'));
    await tester.pumpAndSettle();
    expect(api.calls, contains('join:87654321:null:${'b' * 64}'));
    expect(find.byType(AlertDialog), findsNothing);
    expect(find.text('返回房间'), findsOneWidget);
    expect(tester.takeException(), isNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('malformed invitation UTF-8 remains a validation error', (
    tester,
  ) async {
    final api = await pump(tester, enterRoom: false);
    await tester.tap(find.text('加入房间'));
    await tester.pumpAndSettle();
    for (final invalid in ['%FF', '%F0%9F']) {
      await tester.enterText(
        find.byKey(const ValueKey('房间号')),
        'p2wlan://join?server=https%3A%2F%2Fcontrol.example&room=12345678#invite=$invalid',
      );
      await tester.pump();
      await tester.tap(find.text('确认'));
      await tester.pumpAndSettle();
      expect(find.text('邀请链接格式无效'), findsOneWidget);
      expect(tester.takeException(), isNull);
    }
    expect(api.calls.where((call) => call.startsWith('join:')), isEmpty);
    await tester.tap(find.text('取消'));
    await tester.pumpAndSettle();
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'failed list refresh keeps cached room presence visibly stale after dismissing the banner',
    (tester) async {
      final api = await pump(tester);
      api.listError = '房间列表暂时不可用';
      await tester.pump(const Duration(seconds: 6));
      await tester.pumpAndSettle();
      expect(find.text('在线'), findsNothing);
      expect(find.text('状态待更新'), findsOneWidget);
      await tester.tap(find.byTooltip('关闭提示'));
      await tester.pumpAndSettle();
      expect(find.text('状态待更新'), findsOneWidget);
      expect(find.textContaining('当前显示上次数据'), findsOneWidget);
      api.listError = null;
      await tester.ensureVisible(
        find.byKey(const ValueKey('retry-room-roster')),
      );
      await tester.pumpAndSettle();
      await tester.tap(find.byKey(const ValueKey('retry-room-roster')));
      await tester.pumpAndSettle();
      expect(find.text('在线'), findsOneWidget);
      expect(find.textContaining('当前显示上次数据'), findsNothing);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'one join entry accepts an invitation without sending a password',
    (tester) async {
      final api = await pump(tester, enterRoom: false);
      expect(find.text('粘贴邀请'), findsNothing);
      await tester.tap(find.text('加入房间'));
      await tester.pumpAndSettle();
      final invitation = RoomInvitation(
        'https://control.example',
        '12345678',
        'a' * 64,
      ).toUri().toString();
      await tester.enterText(find.byKey(const ValueKey('房间号')), invitation);
      await tester.pumpAndSettle();
      expect(find.byKey(const ValueKey('房间密码')), findsNothing);
      expect(api.calls.where((call) => call.startsWith('join:')), isEmpty);
      await tester.tap(find.text('确认'));
      await tester.pumpAndSettle();
      expect(api.calls, contains('join:12345678:null:${'a' * 64}'));
      expect(find.text('设备与连接 · 1'), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('roster failure retains selected room and retries in place', (
    tester,
  ) async {
    final api = await pump(
      tester,
      configureApi: (api) => api.rosterError = '成员信息请求失败',
    );
    expect(find.text('朋友房间'), findsOneWidget);
    expect(find.text('暂时无法加载房间详情。'), findsOneWidget);
    expect(find.text('房间号 12345678 · 10.21.1.0/24'), findsOneWidget);
    api.rosterError = null;
    await tester.tap(find.byKey(const ValueKey('retry-room-roster')));
    await tester.pumpAndSettle();
    expect(find.text('设备与连接 · 1'), findsOneWidget);
    expect(find.byKey(const ValueKey('retry-room-roster')), findsNothing);
    expect(find.text('返回房间'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('failed roster refresh marks cached device state as outdated', (
    tester,
  ) async {
    final api = await pump(tester);
    api.rosterError = '更新失败';
    await tester.pump(const Duration(seconds: 6));
    await tester.pumpAndSettle();
    expect(find.text('10.21.1.3'), findsOneWidget);
    expect(find.textContaining('当前显示上次数据'), findsOneWidget);
    expect(find.text('状态待更新'), findsOneWidget);
    expect(find.text('在线'), findsNothing);
    expect(find.text('成员信息待更新'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('invite failure does not hide a successful room roster', (
    tester,
  ) async {
    final api = await pump(
      tester,
      configureApi: (api) => api.inviteError = '邀请请求失败',
    );
    expect(find.text('10.21.1.3'), findsOneWidget);
    await tester.ensureVisible(find.text('邀请管理'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('邀请管理'));
    await tester.pumpAndSettle();
    expect(find.text('邀请信息更新失败'), findsOneWidget);
    expect(find.text('邀请请求失败'), findsOneWidget);
    expect(find.textContaining('尚未生成邀请'), findsNothing);
    api.inviteError = null;
    await tester.ensureVisible(find.text('重试'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('重试'));
    await tester.pumpAndSettle();
    expect(find.text('邀请信息更新失败'), findsNothing);
    expect(find.textContaining('尚未生成邀请'), findsOneWidget);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'existing owner sees why creation is unavailable and a management entry',
    (tester) async {
      await pump(tester, enterRoom: false);
      expect(find.textContaining('每个账号可创建一个房间'), findsOneWidget);
      expect(
        tester
            .widget<FilledButton>(find.widgetWithText(FilledButton, '创建房间'))
            .onPressed,
        isNull,
      );
      await tester.tap(find.text('管理我的房间'));
      await tester.pumpAndSettle();
      expect(find.text('设备与连接 · 1'), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'cards connect and disconnect the local room without opening details',
    (tester) async {
      _RoomRuntime.instances.clear();
      await pump(tester, enterRoom: false, canConnect: true);
      final action = find.byKey(
        const ValueKey('room-card-connection-$_roomId'),
      );
      await tester.tap(action);
      await tester.pumpAndSettle();
      final connected = _RoomRuntime.instances.singleWhere(
        (runtime) => runtime.startCalls == 1,
      );
      expect(connected.startCalls, 1);
      expect(find.text('断开本机'), findsOneWidget);
      expect(find.textContaining('设备与连接'), findsNothing);
      await tester.tap(action);
      await tester.pumpAndSettle();
      expect(connected.stopCalls, 1);
      expect(find.text('连接本机'), findsOneWidget);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('card action is disabled during an existing start operation', (
    tester,
  ) async {
    final started = Completer<void>();
    _RoomRuntime.pendingStart = started;
    addTearDown(() => _RoomRuntime.pendingStart = null);
    await pump(tester, enterRoom: false, canConnect: true);
    final action = find.byKey(const ValueKey('room-card-connection-$_roomId'));
    await tester.tap(action);
    await tester.pump();
    expect(tester.widget<FilledButton>(action).onPressed, isNull);
    started.complete();
    await tester.pumpAndSettle();
    expect(tester.widget<FilledButton>(action).onPressed, isNotNull);
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets('management-only platforms hide local connection actions', (
    tester,
  ) async {
    await pump(tester, enterRoom: false);
    expect(
      find.byKey(const ValueKey('room-card-connection-$_roomId')),
      findsNothing,
    );
    await tester.pumpWidget(const SizedBox.shrink());
  });

  testWidgets(
    'room overview and device rows support narrow screens and large text',
    (tester) async {
      tester.view.physicalSize = const Size(360, 1200);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await pump(tester, enterRoom: false, textScale: 2);
      expect(tester.takeException(), isNull);
      await tester.ensureVisible(
        find.byKey(const ValueKey('room-card-$_roomId')),
      );
      await tester.tap(find.byKey(const ValueKey('room-card-$_roomId')));
      await tester.pumpAndSettle();
      expect(find.text('10.21.1.3'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets(
    'compact room detail prioritizes remote devices and folds connection preferences',
    (tester) async {
      tester.view.physicalSize = const Size(360, 800);
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      await pump(
        tester,
        snapshot: _snapshot(),
        canConnect: true,
        textScale: 1.5,
      );
      expect(tester.getTopLeft(find.text('10.21.1.3')).dy, lessThan(800));
      expect(
        tester
            .getTopLeft(find.byKey(const ValueKey('room-device-device-1')))
            .dy,
        lessThan(
          tester
              .getTopLeft(find.byKey(const ValueKey('room-device-10.21.1.2')))
              .dy,
        ),
      );
      expect(find.text('启动时自动连接此房间'), findsNothing);
      expect(find.byTooltip('复制房间号'), findsOneWidget);
      await tester.ensureVisible(find.text('连接与自动连接'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('连接与自动连接'));
      await tester.pumpAndSettle();
      expect(find.text('启动时自动连接此房间'), findsOneWidget);
      expect(find.text('10.21.1.0/24'), findsOneWidget);
      expect(tester.takeException(), isNull);
      await tester.pumpWidget(const SizedBox.shrink());
    },
  );

  testWidgets('room roster readdress cannot borrow an old Direct label', (
    tester,
  ) async {
    final mismatched = DiagnosticsSnapshot.fromJson({
      ..._snapshot().raw,
      'peers': [
        {
          'node_id': 'device-1',
          'virtual_ip': '10.21.1.9',
          'device_name': '好友电脑',
          'online': true,
          'active_path': 'direct',
          'state': 'direct',
          'direct': {'latency_ms': 18, 'last_success_age_ms': 0},
        },
      ],
    });
    await pump(tester, role: 'member', snapshot: mismatched);
    final card = find.byKey(const ValueKey('room-device-device-1'));
    await tester.ensureVisible(card);
    await tester.pumpAndSettle();
    expect(find.descendant(of: card, matching: find.text('直连')), findsNothing);
    expect(
      find.descendant(of: card, matching: find.text('18 ms')),
      findsNothing,
    );
    expect(
      find.descendant(of: card, matching: find.text('地址待同步')),
      findsWidgets,
    );
    await tester.tap(card);
    await tester.pumpAndSettle();
    expect(
      find.descendant(of: find.byType(Dialog), matching: find.text('18 ms')),
      findsNothing,
    );
    await tester.pumpWidget(const SizedBox.shrink());
  });

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
    final colors = P2WlanColors.of(tester.element(find.text('离线')));
    expect(badge.style?.color, colors.neutralText);
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
      expect(find.widgetWithText(AlertDialog, '加入房间'), findsOneWidget);
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
    expect(find.text('状态待更新'), findsNWidgets(3));
    expect(find.text('链路 / 数据'), findsOneWidget);
    expect(find.text('直连'), findsNothing);
    expect(find.text('近期已收房间数据'), findsNothing);
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
  testWidgets('join errors stay inline with inputs and allow corrected retry', (
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
    expect(
      find.descendant(
        of: find.byType(AlertDialog),
        matching: find.text(api.joinError!),
      ),
      findsOneWidget,
    );
    TextField field(String key) => tester.widget<TextField>(
      find.descendant(
        of: find.byKey(ValueKey(key)),
        matching: find.byType(TextField),
      ),
    );
    expect(field('房间号').controller!.text, '87654321');
    expect(field('房间密码').controller!.text, 'wrong-pass');
    await tester.pump(const Duration(seconds: 6));
    await tester.pumpAndSettle();
    expect(find.text(api.joinError!), findsOneWidget);
    expect(find.byTooltip('关闭提示'), findsNothing);
    expect(field('房间密码').enabled, isTrue);
    api.joinError = null;
    await tester.enterText(find.byKey(const ValueKey('房间密码')), 'correct-pass');
    await tester.tap(find.text('确认'));
    await tester.pumpAndSettle();
    expect(api.calls.where((call) => call.startsWith('join:')), [
      'join:87654321:wrong-pass:null',
      'join:87654321:correct-pass:null',
    ]);
    expect(find.byType(AlertDialog), findsNothing);
    expect(find.text('返回房间'), findsOneWidget);
    expect(find.text('房间加入失败：房间密码不正确'), findsNothing);
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
    expect(find.text('部分链路已建立'), findsWidgets);
    expect(find.text('直连已建立'), findsNothing);
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
          'node_id': 'device-1',
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
          'node_id': 'device-1',
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
    expect(find.text('中继已建立'), findsWidgets);
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
          'node_id': 'device-1',
          'online': true,
          'active_path': 'relay',
          'state': 'connecting',
        },
      ],
    });
    expect(snap.peers.single.isRelayVerified, isFalse);
    await pump(tester, snapshot: snap, enterRoom: false);
    final readyLabels = find.textContaining('中继已建立').evaluate().length;
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
