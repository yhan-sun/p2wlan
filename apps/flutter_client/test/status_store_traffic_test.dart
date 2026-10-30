import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';

void main() {
  for (final change in <String, Map<String, Object?>>{
    'PID': {'process_id': 43},
    'runtime': {'runtime_incarnation': 2},
    'local node': {'node_id': 'replacement-local'},
    'network': {'network_id': 'replacement-network'},
    'network generation': {'network_generation': 8},
    'uptime reset': {'uptime_ms': 1},
  }.entries) {
    test(
      'traffic ${change.key} with larger counters resets before throttle',
      () async {
        final harness = await _Harness.create();
        addTearDown(harness.dispose);
        await harness.prime();
        await harness.sample(10000, snapshot: change.value, silent: true);
        harness.expectNoRates();
        await harness.sample(11000, snapshot: change.value);
        harness.expectRates();
      },
    );
  }

  for (final change in <String, Map<String, Object?>>{
    'peer IP': {'virtual_ip': '10.20.0.3'},
    'peer lifecycle': {
      'path_observability': {
        'network_epoch': {'peer_session_generation': 2},
      },
    },
    'node ID': {'node_id': 'replacement-peer'},
  }.entries) {
    test(
      'traffic ${change.key} replacement cannot reuse a prior rate',
      () async {
        final harness = await _Harness.create();
        addTearDown(harness.dispose);
        await harness.prime();
        await harness.sample(10000, peer: change.value, silent: true);
        harness.expectNoRates();
        await harness.sample(11000, peer: change.value);
        harness.expectNoRates();
        await harness.sample(12000, peer: change.value);
        harness.expectRates(
          peerId: change.value['node_id'] as String? ?? 'peer',
        );
      },
    );
  }

  for (final change in <String, Map<String, Object?>>{
    'stale catalog': {'peer_snapshot_stale': true},
    'captured revision mismatch': {'captured_revision': -1},
    'incomplete catalog': {
      'stats': {'total_peers': 2},
    },
  }.entries) {
    test('traffic ${change.key} clears baseline before throttle', () async {
      final harness = await _Harness.create();
      addTearDown(harness.dispose);
      await harness.prime();
      await harness.sample(10000, snapshot: change.value, silent: true);
      harness.expectNoRates();
      await harness.sample(11000, silent: true);
      harness.expectNoRates();
      await harness.sample(12000);
      harness.expectRates();
    });
  }

  for (final change in <String, Map<String, Object?>>{
    'missing upload': {'bytes_sent': null},
    'missing download': {'bytes_received': null},
    'negative upload': {'bytes_sent': -1},
    'negative download': {'bytes_received': -1},
    'offline peer': {'online': false},
  }.entries) {
    test(
      'traffic ${change.key} removes old rates and awaits a baseline',
      () async {
        final harness = await _Harness.create();
        addTearDown(harness.dispose);
        await harness.prime();
        await harness.sample(10000, peer: change.value, silent: true);
        harness.expectNoRates();
        await harness.sample(11000);
        harness.expectNoRates();
        await harness.sample(12000);
        harness.expectRates();
      },
    );
  }

  test(
    'removed peer rates do not survive throttle or a later rejoin',
    () async {
      final harness = await _Harness.create();
      addTearDown(harness.dispose);
      await harness.prime();
      await harness.sample(10000, removed: true, silent: true);
      harness.expectNoRates();
      await harness.sample(11000);
      harness.expectNoRates();
      await harness.sample(12000);
      harness.expectRates();
    },
  );

  for (final direction in ['bytes_sent', 'bytes_received']) {
    test(
      '$direction reset establishes a baseline without a false zero rate',
      () async {
        final harness = await _Harness.create();
        addTearDown(harness.dispose);
        await harness.prime();
        await harness.sample(10000, peer: {direction: 0}, silent: true);
        harness.expectNoRates();
        await harness.sample(11000);
        harness.expectNoRates();
        await harness.sample(12000);
        harness.expectRates();
      },
    );
  }

  test(
    'unchanged zero counters are a measured zero after two samples',
    () async {
      final harness = await _Harness.create();
      addTearDown(harness.dispose);
      await harness.sample(0);
      harness.expectNoRates();
      await harness.sample(0);
      final rate = harness.store.peerDirectionalTransferRates['peer'];
      expect(rate, isNotNull);
      expect(rate!.uploadBytesPerSecond, 0);
      expect(rate.downloadBytesPerSecond, 0);
    },
  );

  test(
    'health failure retained snapshot cannot bridge traffic samples',
    () async {
      final harness = await _Harness.create();
      addTearDown(harness.dispose);
      await harness.prime();
      harness.api.healthy = false;
      await harness.store.refresh(silent: true);
      expect(harness.store.snapshotStale, isTrue);
      harness.expectNoRates();
      harness.api.healthy = true;
      await harness.sample(11000);
      harness.expectNoRates();
      await harness.sample(12000);
      harness.expectRates();
    },
  );

  testWidgets('snapshot expiry clears samples before the next fresh catalog', (
    tester,
  ) async {
    final harness = (await tester.runAsync(
      () => _Harness.create(expire: true),
    ))!;
    try {
      await harness.prime();
      await tester.pump(const Duration(seconds: 1));
      expect(harness.store.snapshotStale, isTrue);
      harness.expectNoRates();
      await harness.sample(11000);
      harness.expectNoRates();
      await harness.sample(12000);
      harness.expectRates();
    } finally {
      harness.dispose();
    }
  });

  test(
    'snapshot revisions advance without changing the traffic owner',
    () async {
      final harness = await _Harness.create();
      addTearDown(harness.dispose);
      await harness.prime();
      await harness.sample(300);
      harness.expectRates();
      expect(harness.store.snapshot!.revision, 3);
    },
  );
}

class _Harness {
  _Harness(this.directory, this.settings, this.api, this.store);

  final Directory directory;
  final SettingsStore settings;
  final _TrafficApi api;
  final StatusStore store;
  var revision = 0;

  static Future<_Harness> create({bool expire = false}) async {
    final directory = await Directory.systemTemp.createTemp('traffic_fixture_');
    final settings = SettingsStore(
      settingsFile: File('${directory.path}/settings.json'),
      tokenRepository: InMemorySecureTokenRepository(),
    );
    await settings.load();
    final api = _TrafficApi();
    final store = StatusStore(
      settingsStore: settings,
      diagnosticsApi: api,
      enableEventPolling: false,
      metricsUpdateInterval: const Duration(hours: 1),
      enableFreshnessTimer: expire,
      maxSnapshotAge: const Duration(seconds: 1),
    );
    return _Harness(directory, settings, api, store);
  }

  Future<void> prime() async {
    await sample(100);
    expectNoRates();
    await sample(200);
    expectRates();
  }

  Future<void> sample(
    int bytes, {
    Map<String, Object?> snapshot = const {},
    Map<String, Object?> peer = const {},
    bool removed = false,
    bool silent = false,
  }) async {
    revision++;
    api.snapshot = DiagnosticsSnapshot.fromJson({
      'process_id': 42,
      'runtime_incarnation': 1,
      'node_id': 'local-fixture',
      'virtual_ip': '10.20.0.1',
      'network_id': 'default',
      'network_generation': 7,
      'revision': revision,
      'captured_revision': revision,
      'uptime_ms': revision * 1000,
      'peers': [
        if (!removed)
          {
            'node_id': 'peer',
            'virtual_ip': '10.20.0.2',
            'online': true,
            'state': 'direct',
            'active_path': 'direct',
            'bytes_sent': bytes,
            'bytes_received': bytes,
            'path_observability': {
              'network_epoch': {'peer_session_generation': 1},
            },
            ...peer,
          },
      ],
      'stats': {'total_peers': removed ? 0 : 1},
      'health': {'status': 'healthy', 'control_connected': true},
      ...snapshot,
    });
    await store.refresh(silent: silent);
  }

  void expectNoRates() {
    expect(store.peerTransferRatesBytesPerSecond, isEmpty);
    expect(store.peerDirectionalTransferRates, isEmpty);
  }

  void expectRates({String peerId = 'peer'}) {
    final rate = store.peerDirectionalTransferRates[peerId];
    expect(rate, isNotNull);
    expect(rate!.uploadBytesPerSecond, greaterThan(0));
    expect(rate.downloadBytesPerSecond, greaterThan(0));
    expect(
      store.peerTransferRatesBytesPerSecond[peerId],
      rate.uploadBytesPerSecond + rate.downloadBytesPerSecond,
    );
  }

  void dispose() {
    store.dispose();
    settings.dispose();
    directory.deleteSync(recursive: true);
  }
}

class _TrafficApi extends DiagnosticsApi {
  late DiagnosticsSnapshot snapshot;
  bool healthy = true;

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async => healthy;

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async =>
      snapshot;

  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) async =>
      const RoutesResponse(
        contractVersion: 1,
        interfaceName: 'fixture',
        mtu: 1420,
        healthy: true,
        conflictCount: 0,
        entries: [],
      );
}
