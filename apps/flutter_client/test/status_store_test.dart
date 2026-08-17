import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';

void main() {
  test(
    'refresh discards an old diagnostics URL response and retries the new URL',
    () async {
      final fixture = await _loadFixture();
      final oldHealth = Completer<void>();
      final api = _SwitchingDiagnosticsApi(
        snapshot: fixture,
        oldHealth: oldHealth,
      );
      final stores = await _makeStores(api);
      addTearDown(stores.dispose);

      final firstRefresh = stores.statusStore.refresh();
      await api.oldHealthStarted.future;
      await stores.settingsStore.updateDiagnosticsUrl(
        'http://localhost:39278/status',
      );
      oldHealth.complete();
      await firstRefresh;

      expect(api.healthUrls, contains('http://127.0.0.1:39277/status'));
      expect(api.healthUrls, contains('http://localhost:39278/status'));
      expect(stores.statusStore.snapshot?.nodeId, fixture.nodeId);
      expect(stores.statusStore.lastError, isNull);
    },
  );

  test(
    'marks an unchanged snapshot stale after its freshness deadline',
    () async {
      final api = _SwitchingDiagnosticsApi(snapshot: await _loadFixture());
      final stores = await _makeStores(
        api,
        maxSnapshotAge: const Duration(milliseconds: 1),
      );
      addTearDown(stores.dispose);

      await stores.statusStore.refresh();
      expect(stores.statusStore.snapshotStale, isFalse);
      await Future<void>.delayed(const Duration(milliseconds: 10));

      expect(stores.statusStore.snapshotStale, isTrue);
      expect(stores.statusStore.snapshot, isNotNull);
    },
  );
}

Future<DiagnosticsSnapshot> _loadFixture() async {
  final raw =
      jsonDecode(
            await File('test/fixtures/status_connected.json').readAsString(),
          )
          as Map<String, dynamic>;
  return DiagnosticsSnapshot.fromJson(raw);
}

Future<_Stores> _makeStores(
  DiagnosticsApi api, {
  Duration maxSnapshotAge = StatusStore.defaultMaxSnapshotAge,
}) async {
  final tempDir = await Directory.systemTemp.createTemp('p2wlan_status_store_');
  final settingsStore = SettingsStore(
    settingsFile: File('${tempDir.path}/settings.json'),
  );
  await settingsStore.load();
  final statusStore = StatusStore(
    settingsStore: settingsStore,
    diagnosticsApi: api,
    maxSnapshotAge: maxSnapshotAge,
    enableFreshnessTimer: true,
  );
  return _Stores(tempDir, settingsStore, statusStore);
}

class _Stores {
  const _Stores(this.directory, this.settingsStore, this.statusStore);

  final Directory directory;
  final SettingsStore settingsStore;
  final StatusStore statusStore;

  void dispose() {
    statusStore.dispose();
    settingsStore.dispose();
    if (directory.existsSync()) directory.deleteSync(recursive: true);
  }
}

class _SwitchingDiagnosticsApi implements DiagnosticsApi {
  _SwitchingDiagnosticsApi({required this.snapshot, this.oldHealth});

  final DiagnosticsSnapshot snapshot;
  final Completer<void>? oldHealth;
  final oldHealthStarted = Completer<void>();
  final healthUrls = <String>[];

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) async {
    healthUrls.add(diagnosticsUrl);
    if (diagnosticsUrl.contains('127.0.0.1') && oldHealth != null) {
      oldHealthStarted.complete();
      await oldHealth!.future;
    }
    return true;
  }

  @override
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async =>
      snapshot;

  @override
  Future<bool> requestShutdown(String diagnosticsUrl) async => true;

  @override
  Future<SpeedTestResult> runSpeedTest(
    String diagnosticsUrl, {
    required String peerVirtualIp,
    Duration duration = const Duration(seconds: 10),
  }) async {
    throw UnimplementedError();
  }

  @override
  Future<({int revision, List<Map<String, dynamic>> events})> fetchEvents(
    String diagnosticsUrl, {
    int since = 0,
    Duration timeout = const Duration(seconds: 30),
  }) async => throw UnimplementedError();

  @override
  Future<({List<Map<String, dynamic>> peers, int total, String? nextCursor})>
  fetchPeers(String diagnosticsUrl, {String? cursor, int limit = 100}) async =>
      throw UnimplementedError();

  @override
  Future<String> fetchLogTail(
    String diagnosticsUrl, {
    int lines = 120,
    int maxBytes = 262144,
  }) async => throw UnimplementedError();

  @override
  Future<Map<String, dynamic>> verifyRoutes(String diagnosticsUrl) async =>
      throw UnimplementedError();

  @override
  Future<Map<String, dynamic>> repairRoutes(String diagnosticsUrl) async =>
      throw UnimplementedError();

  @override
  void close() {}
}
