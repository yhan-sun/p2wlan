import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/rooms/desktop_room_runtime.dart';
import 'package:p2wlan_flutter_client/core/rooms/parallel_rooms.dart';
import 'package:p2wlan_flutter_client/core/rooms/route_inventory.dart';

import 'parallel_rooms_test.dart' as fixtures;

class _RoomApi extends DiagnosticsApi {
  _RoomApi(this.plan);
  final ParallelRoomPlan plan;
  bool wrongNetwork = false;
  bool brokenStatus = true;
  @override
  Future<RoutesResponse> verifyRoutes(String url) async => const RoutesResponse(
    contractVersion: 1,
    interfaceName: 'room-test',
    mtu: 1420,
    healthy: true,
    conflictCount: 0,
    entries: [],
  );
  @override
  Future<bool> fetchHealth(String url) async => false;
  @override
  Future<DiagnosticsSnapshot> fetchStatus(String url) async {
    if (brokenStatus) throw StateError('stale process');
    return DiagnosticsSnapshot.fromJson({
      'network_id': wrongNetwork ? 'another-room' : plan.room.id,
      'virtual_ip': '10.21.1.2',
    });
  }
}

class _RoomDaemon extends DaemonController {
  _RoomDaemon(_RoomApi api) : super(diagnosticsApi: api);
  final operations = <String>[];
  bool stopWorks = true;
  bool running = false;
  bool failDiscovery = false;
  @override
  Future<bool> hasRoomRuntime() async {
    if (failDiscovery) throw StateError('process query failed');
    return running;
  }

  String? conflict;
  @override
  Future<DaemonCommandResult> stop(String url) async {
    operations.add('stop');
    if (stopWorks) running = false;
    return DaemonCommandResult(ok: stopWorks, message: 'stop');
  }

  @override
  Future<DaemonCommandResult> start(
    AppSettings settings, {
    int? vpnSettingsRevision,
  }) async {
    operations.add('start');
    running = true;
    return const DaemonCommandResult(ok: true, message: 'start');
  }
}

void main() {
  late _RoomApi api;
  late _RoomDaemon daemon;
  late DesktopRoomRuntime runtime;
  setUp(() {
    final plan = ParallelRoomPlan(
      AppSettings(
        authToken: fixtures.token('a'),
        controlServer: 'https://control.example',
      ),
      fixtures.room(1),
    );
    api = _RoomApi(plan);
    daemon = _RoomDaemon(api);
    runtime = DesktopRoomRuntime(
      plan,
      diagnosticsApi: api,
      daemonController: daemon,
      hasCredentials: () async => true,
      checkRoutes: (cidr) async {
        daemon.operations.add('routes');
        return daemon.conflict;
      },
    );
  });
  tearDown(() => runtime.close());

  test('stale credentials alone do not represent a running room', () async {
    expect(await runtime.exists(), isFalse);
    expect(daemon.operations, isEmpty);
  });

  test('live room with unavailable diagnostics remains recoverable', () async {
    daemon.running = true;
    expect(await runtime.exists(), isTrue);
    expect(api.brokenStatus, isTrue);
  });

  test(
    'live room without credentials can still be discovered for cleanup',
    () async {
      daemon.running = true;
      final missingCredentials = DesktopRoomRuntime(
        api.plan,
        diagnosticsApi: api,
        daemonController: daemon,
        hasCredentials: () async => false,
      );
      expect(await missingCredentials.exists(), isTrue);
    },
  );

  test('process discovery requires an explicit room scope', () async {
    final unscoped = DaemonController(diagnosticsApi: api);
    await expectLater(unscoped.hasRoomRuntime(), throwsStateError);
  });

  test('process query failure is not reported as an absent room', () async {
    daemon.failDiscovery = true;
    await expectLater(runtime.exists(), throwsStateError);
  });

  test(
    'disconnect then refresh with stale credentials allows reconnect',
    () async {
      final settings = AppSettings(
        authToken: fixtures.token('a'),
        controlServer: 'https://control.example',
      );
      final manager = ParallelRooms(
        readSettings: () => settings,
        supported: true,
        refreshInterval: Duration.zero,
        runtimeFactory: (plan) => DesktopRoomRuntime(
          plan,
          diagnosticsApi: api,
          daemonController: daemon,
          // Simulate the file that survives a forced exit and later stop calls.
          hasCredentials: () async => true,
          checkRoutes: (_) async => null,
        ),
      );
      addTearDown(() async {
        await manager.stopAll();
        manager.dispose();
      });
      final room = fixtures.room(1);
      daemon.running = true;
      await manager.recover(room);
      expect(manager.session(room.id)!.phase, RoomConnectionPhase.unavailable);
      expect((await manager.disconnect(room.id)).ok, isTrue);
      await manager.recover(room);
      await manager.recover(room);
      expect(manager.session(room.id), isNull);
      api.brokenStatus = false;
      expect((await manager.connect(room)).ok, isTrue);
      expect(manager.session(room.id)!.phase, RoomConnectionPhase.running);
      expect(
        daemon.operations.where((operation) => operation == 'start'),
        hasLength(1),
      );
    },
  );

  test('own stale runtime is stopped before checking routes', () async {
    expect((await runtime.start()).ok, isTrue);
    expect(daemon.operations, ['stop', 'routes', 'start']);
  });
  test(
    'failed stale cleanup does not ignore overlapping routes or launch',
    () async {
      daemon.stopWorks = false;
      expect((await runtime.start()).ok, isFalse);
      expect(daemon.operations, ['stop']);
    },
  );
  test(
    'a real conflicting VPN still blocks launch after own cleanup',
    () async {
      daemon.conflict = nativeRoomConflictMessage(
        '10.21.1.0/24',
        const NativeIpv4Route('10.0.0.0/8', 'Other VPN'),
      );
      final result = await runtime.start();
      expect(result.ok, isFalse);
      expect(result.message, contains('Other VPN'));
      expect(daemon.operations, ['stop', 'routes']);
    },
  );
  test('authenticated different room is never stopped', () async {
    api.brokenStatus = false;
    api.wrongNetwork = true;
    expect((await runtime.start()).ok, isFalse);
    expect(daemon.operations, isEmpty);
  });
}
