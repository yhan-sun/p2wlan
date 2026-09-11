import 'dart:async';
import 'dart:convert';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/daemon/daemon_controller.dart';
import 'package:p2wlan_flutter_client/core/daemon/runtime_identity.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/rooms/parallel_rooms.dart';
import 'package:p2wlan_flutter_client/core/rooms/room_api.dart';

String token(String account) =>
    'a.${base64Url.encode(utf8.encode(jsonEncode({'user_id': account})))}.b';

FriendRoom room(int number, {int? subnet}) => FriendRoom(
  id: 'room-${number.toRadixString(16).padLeft(32, '0')}',
  code: number.toString().padLeft(8, '0'),
  name: 'Room $number',
  cidr: '10.21.${subnet ?? number}.0/24',
  ownerId: 'owner',
  role: 'member',
  locked: false,
);

class FakeRuntime implements RoomRuntime {
  FakeRuntime(this.plan);
  final ParallelRoomPlan plan;
  int starts = 0;
  int stops = 0;
  bool closed = false;
  bool present = false;
  bool failStop = false;
  bool failStart = false;
  bool failStatus = false;
  bool wrongNetwork = false;
  Completer<void>? startGate;
  Completer<void>? stopGate;

  @override
  Future<bool> exists() async => present;

  @override
  Future<DaemonCommandResult> start() async {
    starts++;
    await startGate?.future;
    return DaemonCommandResult(ok: !failStart, message: 'start');
  }

  @override
  Future<DaemonCommandResult> stop() async {
    stops++;
    await stopGate?.future;
    return DaemonCommandResult(
      ok: !failStop,
      message: 'stop',
      graceful: !failStop,
    );
  }

  @override
  Future<DiagnosticsSnapshot> status() async {
    if (failStatus) throw StateError('unavailable');
    return DiagnosticsSnapshot.fromJson({
      'network_id': wrongNetwork ? room(200).id : plan.room.id,
      'virtual_ip': plan.room.cidr.replaceFirst('.0/24', '.2'),
      'ready_phase': 'discovering_peers',
    });
  }

  @override
  void close() => closed = true;
}

void main() {
  late AppSettings settings;
  late ParallelRooms manager;
  late Map<String, FakeRuntime> runtimes;
  late void Function(FakeRuntime)? configure;

  setUp(() {
    settings = AppSettings(
      authToken: token('owner'),
      controlServer: 'https://control.example',
    );
    runtimes = {};
    configure = null;
    manager = ParallelRooms(
      readSettings: () => settings,
      supported: true,
      refreshInterval: Duration.zero,
      runtimeFactory: (plan) {
        final runtime = FakeRuntime(plan);
        configure?.call(runtime);
        runtimes[plan.room.id] = runtime;
        return runtime;
      },
    );
  });

  tearDown(() async {
    for (final runtime in runtimes.values) {
      runtime.failStop = false;
      if (runtime.startGate != null && !runtime.startGate!.isCompleted) {
        runtime.startGate!.complete();
      }
      if (runtime.stopGate != null && !runtime.stopGate!.isCompleted) {
        runtime.stopGate!.complete();
      }
    }
    await manager.stopAll();
    manager.dispose();
  });

  test(
    'room diagnostics collision chooses and persists an independent port',
    () async {
      final firstRoom = room(1);
      final initial = ParallelRoomPlan(settings, firstRoom);
      final primaryPort = Uri.parse(initial.settings.diagnosticsUrl).port;
      settings = settings.copyWith(
        diagnosticsUrl: initial.settings.diagnosticsUrl,
      );
      expect((await manager.connect(firstRoom)).ok, isTrue);
      final allocated = manager.session(firstRoom.id)!.plan;
      final chosen = Uri.parse(allocated.settings.diagnosticsUrl).port;
      expect(chosen, isNot(primaryPort));
      expect(
        (await manager.connectionPreference(firstRoom)).diagnosticsPort,
        chosen,
      );
      final secondRoom = room(2);
      final secondProfile = ParallelRoomPlan(settings, secondRoom).profileId;
      await manager.preferences.update(secondProfile, diagnosticsPort: chosen);
      expect((await manager.connect(secondRoom)).ok, isTrue);
      expect(
        Uri.parse(manager.session(secondRoom.id)!.plan.settings.diagnosticsUrl)
            .port,
        isNot(chosen),
      );
      expect(runtimes[firstRoom.id]!.stops, 0);
      await manager.disconnect(firstRoom.id);
      expect((await manager.connect(firstRoom)).ok, isTrue);
      expect(
        Uri.parse(manager.session(firstRoom.id)!.plan.settings.diagnosticsUrl)
            .port,
        chosen,
      );
    },
  );

  test(
    'recovery uses the stored port rather than rehashing a running profile',
    () async {
      final profile = ParallelRoomPlan(settings, room(1)).profileId;
      await manager.preferences.update(profile, diagnosticsPort: 45678);
      configure = (runtime) => runtime.present = true;
      await manager.recover(room(1));
      expect(
        manager.session(room(1).id)!.plan.settings.diagnosticsUrl,
        'http://127.0.0.1:45678/status',
      );
      expect(runtimes[room(1).id]!.starts, 0);
    },
  );

  test(
    'two rooms run concurrently without changing primary settings',
    () async {
      final original = settings;
      final results = await Future.wait([
        manager.connect(room(1)),
        manager.connect(room(2)),
      ]);
      expect(results.every((result) => result.ok), isTrue);
      expect(manager.sessions.length, 2);
      expect(settings, same(original));
      final a = manager.session(room(1).id)!.plan;
      final b = manager.session(room(2).id)!.plan;
      expect(a.profileId, isNot(b.profileId));
      expect(a.settings.tunInterface, isNot(b.settings.tunInterface));
      expect(a.settings.tunInterface.length, lessThanOrEqualTo(15));
      expect(a.settings.diagnosticsUrl, isNot(b.settings.diagnosticsUrl));
      expect(a.settings.udpBind, '0.0.0.0:0');
    },
  );

  test('disconnecting one room leaves the second untouched', () async {
    await manager.connect(room(1));
    await manager.connect(room(2));
    expect((await manager.disconnect(room(1).id)).ok, isTrue);
    expect(manager.session(room(1).id), isNull);
    expect(manager.session(room(2).id)!.phase, RoomConnectionPhase.running);
    expect(runtimes[room(1).id]!.stops, 1);
    expect(runtimes[room(2).id]!.stops, 0);
  });

  test('duplicate connect requests are idempotent', () async {
    final results = await Future.wait(
      List.generate(10, (_) => manager.connect(room(1))),
    );
    expect(results.every((result) => result.ok), isTrue);
    expect(runtimes[room(1).id]!.starts, 1);
  });

  test('overlapping room subnet is refused before launch', () async {
    await manager.connect(room(1));
    expect((await manager.connect(room(2, subnet: 1))).ok, isFalse);
    expect(runtimes.containsKey(room(2).id), isFalse);
    expect(runtimes[room(1).id]!.stops, 0);
  });

  test(
    'an inactive saved prefix does not replace live route validation',
    () async {
      settings = settings.copyWith(overlayCidr: '10.0.0.0/8');
      expect((await manager.connect(room(1))).ok, isTrue);
      expect(runtimes[room(1).id]!.starts, 1);
    },
  );

  test('unchanged credentials do not stop a running room', () async {
    await manager.connect(room(1));
    settings = settings.copyWith(deviceName: 'renamed');
    expect((await manager.credentialsChanged()).ok, isTrue);
    expect(runtimes[room(1).id]!.stops, 0);
    expect(manager.session(room(1).id)!.phase, RoomConnectionPhase.running);
  });

  test('stop all cancels queued starts without leaking a runtime', () async {
    final connecting = manager.connect(room(1));
    final stopped = manager.stopAll();
    expect((await stopped).ok, isTrue);
    expect((await connecting).ok, isFalse);
    expect(manager.sessions, isEmpty);
    expect(runtimes, isEmpty);
  });

  test('stop all drains an in-flight start', () async {
    final gate = Completer<void>();
    configure = (runtime) => runtime.startGate = gate;
    final connecting = manager.connect(room(1));
    await Future<void>.delayed(Duration.zero);
    final stopped = manager.stopAll();
    expect((await manager.connect(room(2))).ok, isFalse);
    gate.complete();
    expect((await connecting).ok, isFalse);
    expect((await stopped).ok, isTrue);
    expect(runtimes[room(1).id]!.stops, 1);
    expect(runtimes[room(1).id]!.closed, isTrue);
    expect(manager.sessions, isEmpty);
  });

  test(
    'account change cancels start and keeps old credentials out of new room',
    () async {
      final gate = Completer<void>();
      configure = (runtime) => runtime.startGate = gate;
      final connecting = manager.connect(room(1));
      await Future<void>.delayed(Duration.zero);
      settings = settings.copyWith(authToken: token('other'));
      expect(manager.allRecentRoomProfileIds, isEmpty);
      expect(manager.exportStatusSummaries(), isEmpty);
      final stopped = manager.credentialsChanged();
      expect(manager.allRecentRoomProfileIds, isEmpty);
      expect(manager.exportStatusSummaries(), isEmpty);
      gate.complete();
      expect((await connecting).ok, isFalse);
      expect((await stopped).ok, isTrue);
      expect(runtimes[room(1).id]!.plan.settings.authToken, token('owner'));
      expect(manager.sessions, isEmpty);
    },
  );

  test(
    'global shutdown keeps admission closed while primary daemon drains',
    () async {
      await manager.connect(room(1));
      final primary = Completer<void>();
      final stopped = manager.withConnectionsPaused(() async {
        await manager.stopAll();
        await primary.future;
      });
      await Future<void>.delayed(Duration.zero);
      expect(manager.sessions, isEmpty);
      expect(manager.connectionsPaused, isTrue);
      expect((await manager.connect(room(2))).ok, isFalse);
      primary.complete();
      await stopped;
      expect(manager.connectionsPaused, isFalse);
      expect((await manager.connect(room(2))).ok, isTrue);
    },
  );

  test('failed stop retains ownership and permits retry', () async {
    await manager.connect(room(1));
    final runtime = runtimes[room(1).id]!;
    runtime.failStop = true;
    expect((await manager.stopAll()).ok, isFalse);
    expect(manager.session(room(1).id)!.phase, RoomConnectionPhase.failed);
    expect(runtime.closed, isFalse);
    runtime.failStop = false;
    expect((await manager.stopAll()).ok, isTrue);
    expect(runtime.closed, isTrue);
  });

  test(
    'bad status does not claim connected or interrupt other rooms',
    () async {
      await manager.connect(room(1));
      configure = (runtime) => runtime.wrongNetwork = true;
      expect((await manager.connect(room(2))).ok, isFalse);
      expect(manager.session(room(2).id)!.snapshot, isNull);
      expect(
        manager.session(room(2).id)!.phase,
        RoomConnectionPhase.unavailable,
      );
      expect(manager.session(room(1).id)!.phase, RoomConnectionPhase.running);
      expect(runtimes[room(1).id]!.stops, 0);
    },
  );

  test('recover adopts an existing room without restarting it', () async {
    configure = (runtime) => runtime.present = true;
    await manager.recover(room(1));
    expect(manager.session(room(1).id)!.phase, RoomConnectionPhase.running);
    expect(runtimes[room(1).id]!.starts, 0);
  });

  test(
    'missing runtime is not automatically started during recovery',
    () async {
      await manager.recover(room(1));
      expect(manager.sessions, isEmpty);
      expect(runtimes[room(1).id]!.starts, 0);
      expect(runtimes[room(1).id]!.closed, isTrue);
    },
  );

  test('profile identity is scoped by account server and room', () {
    final a = ParallelRoomPlan(settings, room(1));
    final b = ParallelRoomPlan(
      settings.copyWith(authToken: token('other')),
      room(1),
    );
    final c = ParallelRoomPlan(
      settings.copyWith(controlServer: 'https://other.example'),
      room(1),
    );
    expect({a.profileId, b.profileId, c.profileId}.length, 3);
    expect(ParallelRoomPlan(settings, room(1)).profileId, a.profileId);
  });

  test('connection count is bounded even with simultaneous requests', () async {
    final results = await Future.wait(
      List.generate(10, (n) => manager.connect(room(n + 1))),
    );
    expect(results.where((result) => result.ok).length, 8);
    expect(manager.sessions.length, 8);
  });

  test(
    'failed startup is cleaned up without forgetting failed cleanup',
    () async {
      configure = (runtime) {
        runtime.failStart = true;
        runtime.failStop = true;
      };
      expect((await manager.connect(room(1))).ok, isFalse);
      expect(manager.session(room(1).id)!.phase, RoomConnectionPhase.failed);
      expect(runtimes[room(1).id]!.closed, isFalse);
    },
  );

  for (final failure in ['start', 'first status']) {
    test(
      'retains a current-account support summary after $failure failure and cleanup',
      () async {
        configure = (runtime) {
          runtime.failStart = failure == 'start';
          runtime.failStatus = failure == 'first status';
        };

        final result = await manager.connect(room(1));
        expect(result.ok, isFalse);
        final profileId = runtimes[room(1).id]!.plan.profileId;
        if (manager.session(room(1).id) != null) {
          expect((await manager.disconnect(room(1).id)).ok, isTrue);
        }

        expect(manager.session(room(1).id), isNull);
        expect(manager.allRecentRoomProfileIds, contains(profileId));
        final summary = jsonDecode(
          manager.exportStatusSummaries()[profileId]!,
        ) as Map<String, dynamic>;
        expect(summary['network_id'], room(1).id);
        expect(summary['profile_id'], profileId);
        expect(summary['phase'], failure == 'start' ? 'failed' : 'unavailable');
        expect(summary['message'], isNotEmpty);

        // Histories belong only to the credential scope that created them.
        settings = settings.copyWith(authToken: token('another-account'));
        expect((await manager.credentialsChanged()).ok, isTrue);
        expect(manager.allRecentRoomProfileIds, isEmpty);
        expect(manager.exportStatusSummaries(), isEmpty);
      },
    );
  }

  test('support log history retains the newest eight room instances', () async {
    for (var number = 1; number <= 9; number++) {
      configure = (runtime) => runtime.failStart = true;
      expect((await manager.connect(room(number))).ok, isFalse);
    }

    final retained = manager.allRecentRoomProfileIds;
    expect(retained, hasLength(8));
    expect(
      retained,
      isNot(contains(ParallelRoomPlan(settings, room(1)).profileId)),
    );
    expect(retained, contains(ParallelRoomPlan(settings, room(9)).profileId));
    expect(manager.supportLogSelection.omittedProfileIds, [
      ParallelRoomPlan(settings, room(1)).profileId,
    ]);
  });

  test('CIDR overlap checks ranges not strings and rejects malformed data', () {
    expect(cidrsOverlap('10.0.0.0/8', '10.21.9.0/24'), isTrue);
    expect(cidrsOverlap('10.21.1.0/24', '10.21.2.0/24'), isFalse);
    expect(cidrsOverlap('0.0.0.0/0', '10.21.1.0/24'), isTrue);
    expect(cidrsOverlap('bad', '10.21.1.0/24'), isTrue);
  });

  test('process matching requires exact instance log identity', () {
    const log = '/tmp/p2wlan/rooms/abc/p2wlan-daemon.log';
    expect(
      daemonCommandMatchesLog('p2wlan-daemon --log-file $log --managed', log),
      isTrue,
    );
    expect(
      daemonCommandMatchesLog('p2wlan-daemon --log-file "$log"', log),
      isTrue,
    );
    expect(
      daemonCommandMatchesLog('p2wlan-daemon --log-file $log.other', log),
      isFalse,
    );
    expect(
      daemonCommandMatchesLog(
        'p2wlan-daemon --log-file $log --build-info',
        log,
      ),
      isFalse,
    );
    expect(
      daemonCommandMatchesLog(
        'p2wlan-daemon --log-file $log --log-file /other',
        log,
      ),
      isFalse,
    );
    expect(
      daemonCommandMatchesLog(
        'p2wlan-daemon --log-file /tmp/personal.log',
        log,
      ),
      isFalse,
    );
    expect(
      daemonCommandMatchesLog(
        'p2wlan-daemon --log-file $log',
        '/tmp/personal.log',
      ),
      isFalse,
    );
  });
}
