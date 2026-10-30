import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/presentation/network_overview.dart';
import 'package:p2wlan_flutter_client/core/traffic/traffic_history_store.dart';

void main() {
  test(
    'first observation is a baseline; repeated samples cannot double count',
    () async {
      final clock = _Clock();
      final store = await _memory(now: clock.call);
      final initial = _scope(sent: 100, received: 200);
      store.observe(settings: _account(), scopes: [initial, initial]);
      _expect(store, 0, 0);
      final started = store.summary(settings: _account())!.startedAt;
      clock.advance();
      final changed = _scope(sent: 150, received: 280, revision: 2);
      store.observe(settings: _account(), scopes: [changed]);
      _expect(store, 50, 80);
      final updated = store.summary(settings: _account())!.updatedAt;
      clock.advance();
      store.observe(settings: _account(), scopes: [changed, changed]);
      _expect(store, 50, 80);
      expect(store.summary(settings: _account())!.startedAt, started);
      expect(store.summary(settings: _account())!.updatedAt, updated);
      expect(updated.isAfter(started), isTrue);
    },
  );

  test(
    'account refresh retains history; account and server changes isolate it',
    () async {
      final store = await _memory();
      store.observe(settings: _account(), scopes: [_scope(sent: 100)]);
      store.observe(
        settings: _account(signature: 'refreshed'),
        scopes: [_scope(sent: 150)],
      );
      _expect(store, 50, 50);
      expect(store.summary(settings: _account(user: 'other-user')), isNull);
      expect(
        store.summary(settings: _account(server: 'https://other.example')),
        isNull,
      );
      store.observe(
        settings: _account(user: 'other-user'),
        scopes: [_scope(sent: 1000)],
      );
      _expect(store, 0, 0, settings: _account(user: 'other-user'));
      _expect(store, 50, 50);
    },
  );

  test('network, local node and peer partitions aggregate without mixing checkpoints', () async {
    final store = await _memory();
    void observe(int bytes) => store.observe(
      settings: _account(),
      scopes: [
        _scope(sent: bytes),
        _scope(sent: bytes * 2, network: 'other-network'),
        _scope(sent: bytes * 3, local: 'other-local'),
        _scope(sent: bytes * 4, peer: 'other-peer'),
      ],
    );
    observe(100);
    observe(110);
    _expect(store, 100, 100);
    _expect(store, 80, 80, network: 'default');
    _expect(store, 60, 60, peer: 'peer-fixture');
    _expect(store, 20, 20, network: 'other-network');
  });

  test('save and reload commit totals and checkpoints together across daemon restarts', () async {
    final file = await _file();
    final first = await _persistent(file);
    first.observe(settings: _account(), scopes: [_scope(sent: 100)]);
    first.observe(settings: _account(), scopes: [_scope(sent: 200)]);
    await first.flush();
    expect(first.dirty, isFalse);
    final second = await _persistent(file);
    second.observe(settings: _account(), scopes: [_scope(sent: 300)]);
    _expect(second, 200, 200);
    second.observe(
      settings: _account(),
      scopes: [_scope(sent: 30, epoch: 101)],
    );
    _expect(second, 230, 230);
    // An older runtime must not be added again after replacement.
    second.observe(
      settings: _account(),
      scopes: [_scope(sent: 10000, epoch: 100)],
    );
    _expect(second, 230, 230);
    await second.flush();
    final third = await _persistent(file);
    third.observe(settings: _account(), scopes: [_scope(sent: 30, epoch: 101)]);
    _expect(third, 230, 230);
    final content = await file.readAsString();
    for (final secret in [
      'account-fixture',
      'control.example',
      'peer-fixture',
      'local-fixture',
      '10.20.',
      'fixture-device',
      _account().authToken,
    ]) {
      expect(content, isNot(contains(secret)));
    }
  });

  test(
    'weak identity reload and ambiguous restarts establish a fresh baseline',
    () async {
      final file = await _file();
      final first = await _persistent(file);
      first.observe(
        settings: _account(),
        scopes: [_scope(sent: 100, epoch: null)],
      );
      first.observe(
        settings: _account(),
        scopes: [_scope(sent: 200, epoch: null)],
      );
      await first.flush();
      final second = await _persistent(file);
      second.observe(
        settings: _account(),
        scopes: [_scope(sent: 1000, epoch: null)],
      );
      _expect(second, 100, 100);
      second.observe(
        settings: _account(),
        scopes: [_scope(sent: 1100, epoch: null)],
      );
      _expect(second, 200, 200);
      second.observe(
        settings: _account(),
        scopes: [_scope(sent: 2000, epoch: null, pid: 43)],
      );
      _expect(second, 200, 200);
      second.observe(
        settings: _account(),
        scopes: [_scope(sent: 2100, epoch: null, pid: 43)],
      );
      _expect(second, 300, 300);
      second.observe(
        settings: _account(),
        scopes: [_scope(sent: 3000, epoch: null, pid: 43, uptime: 1)],
      );
      _expect(second, 300, 300);
    },
  );

  test(
    'generation, peer session and IP changes do not reset cumulative counters',
    () async {
      final store = await _memory();
      store.observe(settings: _account(), scopes: [_scope(sent: 100)]);
      store.observe(
        settings: _account(),
        scopes: [_scope(sent: 150, generation: 2, session: 2, ip: '10.20.0.9')],
      );
      _expect(store, 50, 50);
      store.observe(
        settings: _account(),
        scopes: [
          _scope(sent: 5, generation: 3, session: 3, revision: 2, uptime: 1100),
        ],
      );
      _expect(store, 55, 55);
      store.observe(
        settings: _account(),
        scopes: [_scope(sent: 10, revision: 3, uptime: 1200)],
      );
      _expect(store, 60, 60);
    },
  );

  test(
    'removing a peer preserves totals and its deduplication checkpoint',
    () async {
      final store = await _memory();
      store.observe(settings: _account(), scopes: [_scope(sent: 100)]);
      store.observe(settings: _account(), scopes: [_scope(sent: 200)]);
      store.observe(
        settings: _account(),
        scopes: [_scope(peers: [])],
      );
      _expect(store, 100, 100);
      store.observe(settings: _account(), scopes: [_scope(sent: 200)]);
      _expect(store, 100, 100);
      store.observe(
        settings: _account(),
        scopes: [_scope(sent: 10, revision: 2, uptime: 1100)],
      );
      _expect(store, 110, 110);
    },
  );

  for (final invalid in [
    'stale',
    'captured mismatch',
    'incomplete',
    'missing upload',
    'missing download',
    'negative',
    'stopped',
  ]) {
    test('$invalid does not advance a history checkpoint', () async {
      final store = await _memory();
      store.observe(settings: _account(), scopes: [_scope(sent: 100)]);
      store.observe(
        settings: _account(),
        scopes: [
          _scope(
            sent: 200,
            state: invalid == 'stopped'
                ? NetworkDisplayState.stopped
                : NetworkDisplayState.running,
            snapshot: {
              if (invalid == 'stale') 'peer_snapshot_stale': true,
              if (invalid == 'captured mismatch') 'captured_revision': -1,
              if (invalid == 'incomplete') 'stats': {'total_peers': 2},
            },
            peerFields: {
              if (invalid == 'missing upload') 'bytes_sent': null,
              if (invalid == 'missing download') 'bytes_received': null,
              if (invalid == 'negative') 'bytes_received': -1,
            },
          ),
        ],
      );
      _expect(store, 0, 0);
      store.observe(settings: _account(), scopes: [_scope(sent: 300)]);
      _expect(store, 200, 200);
    });
  }

  test('before load and without a JWT account nothing is recorded', () async {
    final store = TrafficHistoryStore(persistent: false);
    addTearDown(store.dispose);
    store.observe(settings: _account(), scopes: [_scope(sent: 100)]);
    expect(store.summary(settings: _account()), isNull);
    await store.load();
    for (final token in [
      '',
      'invalid',
      'x.${base64Url.encode(utf8.encode('{}'))}.y',
    ]) {
      store.observe(
        settings: _account().copyWith(authToken: token),
        scopes: [_scope(sent: 200)],
      );
    }
    expect(store.summary(settings: _account()), isNull);
    store.observe(settings: _account(), scopes: [_scope(sent: 1000)]);
    _expect(store, 0, 0);
  });

  test(
    'corrupt and oversized files are preserved and loading can be retried',
    () async {
      final file = await _file();
      await file.writeAsString('{broken history');
      final store = await _persistent(file);
      expect(store.loaded, isFalse);
      expect(store.error, 'traffic_history_load_failed');
      store.observe(settings: _account(), scopes: [_scope(sent: 100)]);
      await store.flush();
      expect(await file.readAsString(), '{broken history');
      await file.writeAsString(' ' * (TrafficHistoryStore.maxFileBytes + 1));
      await store.load();
      expect(store.loaded, isFalse);
      expect(await file.length(), TrafficHistoryStore.maxFileBytes + 1);
      await file.writeAsString(jsonEncode({'version': 1, 'records': []}));
      await store.load();
      expect(store.loaded, isTrue);
      expect(store.error, isNull);
    },
  );

  test('invalid persisted dates and capacity flag types are rejected without overwriting', () async {
    final file = await _file();
    final source = await _persistent(file);
    source.observe(settings: _account(), scopes: [_scope(sent: 100)]);
    await source.flush();
    final valid = await file.readAsString();
    final changes = <void Function(Map<String, dynamic>)>[
      (value) => (value['records'] as List).first['updated'] = 8640000000000001,
      (value) {
        (value['records'] as List).first['started'] = 8640000000000001;
        (value['records'] as List).first['updated'] = 8640000000000001;
      },
      for (final invalid in [null, 'true', 1])
        (value) => value['capacity_reached'] = invalid,
    ];
    for (var index = 0; index < changes.length; index++) {
      final value = jsonDecode(valid) as Map<String, dynamic>;
      changes[index](value);
      final content = jsonEncode(value);
      final bad = File('${file.parent.path}/invalid-$index.json');
      await bad.writeAsString(content);
      final store = await _persistent(bad);
      expect(store.loaded, isFalse);
      expect(store.error, 'traffic_history_load_failed');
      expect(store.summary(settings: _account()), isNull);
      store.observe(settings: _account(), scopes: [_scope(sent: 200)]);
      await store.flush();
      expect(await bad.readAsString(), content);
    }
  });

  test('capacity rejects a batch without evicting retained counts', () async {
    final file = await _file();
    final store = await _persistent(file);
    store.observe(settings: _account(), scopes: [_scope(sent: 100)]);
    store.observe(settings: _account(), scopes: [_scope(sent: 200)]);
    store.observe(
      settings: _account(),
      scopes: [
        _scope(
          peers: [
            for (var i = 0; i <= TrafficHistoryStore.maxRecords; i++)
              _peer('capacity-peer-$i', 0, 0),
          ],
        ),
      ],
    );
    expect(store.error, 'traffic_history_capacity');
    _expect(store, 100, 100);
    expect(
      store.summary(settings: _account(), peerId: 'capacity-peer-0'),
      isNull,
    );
    store.observe(settings: _account(), scopes: [_scope(sent: 300)]);
    _expect(store, 200, 200);
    expect(store.error, 'traffic_history_capacity');
    await store.flush();
    final reloaded = await _persistent(file);
    expect(reloaded.error, 'traffic_history_capacity');
    _expect(reloaded, 200, 200);
  });

  test('strong owner rejects old ordering without requiring revision changes for traffic', () async {
    final store = await _memory();
    store.observe(
      settings: _account(),
      scopes: [_scope(sent: 100, revision: 2, uptime: 2000)],
    );
    store.observe(
      settings: _account(),
      scopes: [_scope(sent: 200, revision: 2, uptime: 3000)],
    );
    _expect(store, 100, 100);
    for (final old in [
      _scope(sent: 150, revision: 1, uptime: 4000),
      _scope(sent: 150, revision: 3, uptime: 2500),
      _scope(sent: 150, revision: 2, uptime: 3000),
    ]) {
      store.observe(settings: _account(), scopes: [old]);
      _expect(store, 100, 100);
    }
    // Same revision, later capture: a real record reset can be accumulated.
    store.observe(
      settings: _account(),
      scopes: [_scope(sent: 10, revision: 2, uptime: 4000)],
    );
    _expect(store, 110, 110);
  });

  test(
    'one directional rollback resets the entire retained peer record',
    () async {
      final store = await _memory();
      store.observe(
        settings: _account(),
        scopes: [_scope(sent: 100, received: 100)],
      );
      store.observe(
        settings: _account(),
        scopes: [_scope(sent: 150, received: 200)],
      );
      _expect(store, 50, 100);
      final reset = _scope(sent: 5, received: 300, revision: 2, uptime: 1100);
      store.observe(settings: _account(), scopes: [reset]);
      _expect(store, 55, 400);
      store.observe(settings: _account(), scopes: [reset]);
      _expect(store, 55, 400);
      store.observe(
        settings: _account(),
        scopes: [_scope(sent: 10, received: 350, revision: 3, uptime: 1200)],
      );
      _expect(store, 60, 450);
    },
  );

  test(
    'weak uptime regression cannot double-count a later counter rebound',
    () async {
      final store = await _memory();
      store.observe(
        settings: _account(),
        scopes: [_scope(sent: 100, epoch: null, revision: 1, uptime: 1000)],
      );
      store.observe(
        settings: _account(),
        scopes: [_scope(sent: 200, epoch: null, revision: 2, uptime: 2000)],
      );
      _expect(store, 100, 100);
      store.observe(
        settings: _account(),
        scopes: [_scope(sent: 150, epoch: null, revision: 1, uptime: 1500)],
      );
      _expect(store, 100, 100);
      store.observe(
        settings: _account(),
        scopes: [_scope(sent: 200, epoch: null, revision: 2, uptime: 2000)],
      );
      _expect(store, 100, 100);
      store.observe(
        settings: _account(),
        scopes: [_scope(sent: 210, epoch: null, revision: 3, uptime: 2100)],
      );
      _expect(store, 110, 110);
    },
  );

  test('a save failure retains dirty totals, leaves the old file intact and retries', () async {
    final file = await _file();
    final first = await _persistent(file);
    first.observe(settings: _account(), scopes: [_scope(sent: 100)]);
    await first.flush();
    final committed = await file.readAsString();
    final controlled = _ControlledFile(file)..failDestination = true;
    final store = await _persistent(controlled);
    store.observe(settings: _account(), scopes: [_scope(sent: 200)]);
    await store.flush();
    expect(store.dirty, isTrue);
    expect(store.error, 'traffic_history_save_failed');
    expect(await file.readAsString(), committed);
    _expect(store, 100, 100);
    controlled.failDestination = false;
    await store.flush();
    expect(store.dirty, isFalse);
    expect(store.error, isNull);
    final reloaded = await _persistent(file);
    reloaded.observe(settings: _account(), scopes: [_scope(sent: 200)]);
    _expect(reloaded, 100, 100);
    expect((await file.parent.list().toList()).whereType<File>().length, 1);
  });

  test('flush awaits an existing writer and coalesces observations into one pending snapshot', () async {
    final controlled = _ControlledFile(await _file())..hold = true;
    final store = await _persistent(controlled);
    store.observe(settings: _account(), scopes: [_scope(sent: 100)]);
    final first = store.flush();
    await controlled.started.future;
    expect(store.dirty, isFalse);
    expect(identical(first, store.flush()), isTrue);
    store.observe(settings: _account(), scopes: [_scope(sent: 200)]);
    store.observe(settings: _account(), scopes: [_scope(sent: 300)]);
    expect(identical(first, store.flush()), isTrue);
    controlled.release.complete();
    await first;
    expect(controlled.creates, 2);
    expect(store.saving, isFalse);
    expect(store.dirty, isFalse);
    final reloaded = await _persistent(controlled.file);
    reloaded.observe(settings: _account(), scopes: [_scope(sent: 300)]);
    _expect(reloaded, 200, 200);
  });

  test('one bounded debounce timer saves the latest observation', () async {
    final controlled = _ControlledFile(await _file());
    final store = await _persistent(controlled);
    store.observe(settings: _account(), scopes: [_scope(sent: 100)]);
    store.observe(settings: _account(), scopes: [_scope(sent: 200)]);
    store.observe(settings: _account(), scopes: [_scope(sent: 300)]);
    expect(controlled.creates, 0);
    await controlled.started.future.timeout(const Duration(seconds: 5));
    await store.flush();
    expect(controlled.creates, 1);
    final reloaded = await _persistent(controlled.file);
    _expect(reloaded, 200, 200);
  });
}

AppSettings _account({
  String user = 'account-fixture',
  String server = 'https://control.example',
  String signature = 'fixture',
}) => AppSettings(
  controlServer: server,
  authToken:
      'fixture.${base64Url.encode(utf8.encode(jsonEncode({'user_id': user})))}.$signature',
);

Map<String, Object?> _peer(String id, int? sent, int? received) => {
  'node_id': id,
  'device_name': 'fixture-device',
  'virtual_ip': '10.20.0.2',
  'online': true,
  'state': 'direct',
  'active_path': 'direct',
  'bytes_sent': sent,
  'bytes_received': received,
};

NetworkScopeSnapshot _scope({
  int sent = 0,
  int? received,
  int? epoch = 100,
  int pid = 42,
  int revision = 1,
  int uptime = 1000,
  int generation = 1,
  int session = 1,
  String local = 'local-fixture',
  String network = 'default',
  String peer = 'peer-fixture',
  String ip = '10.20.0.2',
  List<Map<String, Object?>>? peers,
  Map<String, Object?> snapshot = const {},
  Map<String, Object?> peerFields = const {},
  NetworkDisplayState state = NetworkDisplayState.running,
}) {
  final rows =
      peers ??
      [
        {
          ..._peer(peer, sent, received ?? sent),
          'virtual_ip': ip,
          'path_observability': {
            'network_epoch': {
              'network_generation': generation,
              'peer_session_generation': session,
            },
          },
          ...peerFields,
        },
      ];
  final value = DiagnosticsSnapshot.fromJson({
    'node_id': local,
    'virtual_ip': '10.20.0.1',
    'network_id': network,
    'process_id': pid,
    'runtime_incarnation': 1,
    'network_generation': generation,
    'revision': revision,
    'captured_revision': revision,
    'uptime_ms': uptime,
    'connection_timeline': {
      'correlation_id':
          '${local.substring(0, local.length < 8 ? local.length : 8)}-${epoch?.toRadixString(16) ?? 'boot0'}',
    },
    'peers': rows,
    'stats': {'total_peers': rows.length},
    'health': {'status': 'healthy', 'control_connected': true},
    ...snapshot,
  });
  return NetworkScopeSnapshot(
    id: NetworkOverview.primaryScopeId,
    roomId: null,
    name: null,
    profileId: null,
    ownerRevision: 1,
    snapshot: value,
    state: state,
    peers: value.peers,
    transferRates: const {},
  );
}

Future<TrafficHistoryStore> _memory({DateTime Function()? now}) async {
  final store = TrafficHistoryStore(persistent: false, now: now);
  addTearDown(store.dispose);
  await store.load();
  return store;
}

Future<File> _file() async {
  final directory = await Directory.systemTemp.createTemp(
    'traffic_history_fixture_',
  );
  addTearDown(() => directory.delete(recursive: true));
  return File('${directory.path}/history.json');
}

Future<TrafficHistoryStore> _persistent(File file) async {
  final store = TrafficHistoryStore(file: file);
  addTearDown(store.dispose);
  await store.load();
  return store;
}

void _expect(
  TrafficHistoryStore store,
  int sent,
  int received, {
  AppSettings? settings,
  String? network,
  String? peer,
}) {
  final value = store.summary(
    settings: settings ?? _account(),
    networkId: network,
    peerId: peer,
  );
  expect(value, isNotNull);
  expect(value!.counters.uploadBytes, sent);
  expect(value.counters.downloadBytes, received);
  expect(value.counters.totalBytes, sent + received);
}

class _Clock {
  DateTime at = DateTime.utc(2026, 10, 30);
  DateTime call() => at;
  void advance() => at = at.add(const Duration(seconds: 1));
}

class _ControlledFile implements File {
  _ControlledFile(this.file);
  final File file;
  final started = Completer<void>();
  final release = Completer<void>();
  bool hold = false;
  bool failDestination = false;
  int creates = 0;
  int _pathReads = 0;

  @override
  String get path {
    if (failDestination && (++_pathReads).isEven) {
      throw const FileSystemException('fixture rename failure');
    }
    return file.path;
  }

  @override
  Directory get parent => _ControlledDirectory(file.parent, () async {
    creates++;
    if (!started.isCompleted) started.complete();
    if (hold) await release.future;
  });

  @override
  Future<bool> exists() => file.exists();
  @override
  Future<int> length() => file.length();
  @override
  Stream<List<int>> openRead([int? start, int? end]) =>
      file.openRead(start, end);
  @override
  dynamic noSuchMethod(Invocation invocation) => throw UnimplementedError();
}

class _ControlledDirectory implements Directory {
  _ControlledDirectory(this.directory, this.beforeCreate);
  final Directory directory;
  final Future<void> Function() beforeCreate;
  @override
  Future<Directory> create({bool recursive = false}) async {
    await beforeCreate();
    return directory.create(recursive: recursive);
  }

  @override
  dynamic noSuchMethod(Invocation invocation) => throw UnimplementedError();
}
