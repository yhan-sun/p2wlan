import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
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

  test(
    'route verification interval avoids repeating expensive route reads',
    () async {
      final api = _SwitchingDiagnosticsApi(snapshot: await _loadFixture());
      final stores = await _makeStores(
        api,
        routeVerificationInterval: const Duration(hours: 1),
      );
      addTearDown(stores.dispose);

      await stores.statusStore.refresh();
      await stores.statusStore.refresh();

      expect(api.verifyRoutesCount, 1);
    },
  );

  test('rejects a lower revision from the same daemon process', () async {
    final fixture = await _loadFixture();
    final current = _snapshotCopy(
      fixture,
      processId: 42,
      revision: 10,
      uptimeMs: 10000,
    );
    final delayedOld = _snapshotCopy(
      fixture,
      processId: 42,
      revision: 9,
      uptimeMs: 11000,
      peers: const <dynamic>[],
    );
    final api = _SwitchingDiagnosticsApi(
      snapshot: current,
      snapshots: [current, delayedOld],
    );
    final stores = await _makeStores(api);
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await stores.statusStore.refresh();

    expect(stores.statusStore.snapshot?.revision, 10);
    expect(stores.statusStore.snapshot?.peers, isNotEmpty);
  });

  test('accepts a lower revision from a replacement daemon process', () async {
    final fixture = await _loadFixture();
    final oldProcess = _snapshotCopy(
      fixture,
      processId: 42,
      revision: 10,
      uptimeMs: 10000,
    );
    final newProcess = _snapshotCopy(
      fixture,
      processId: 43,
      revision: 1,
      uptimeMs: 100,
      peers: const <dynamic>[],
    );
    final api = _SwitchingDiagnosticsApi(
      snapshot: newProcess,
      snapshots: [oldProcess, newProcess],
    );
    final stores = await _makeStores(api);
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await stores.statusStore.refresh();

    expect(stores.statusStore.snapshot?.processId, 43);
    expect(stores.statusStore.snapshot?.revision, 1);
    expect(stores.statusStore.snapshot?.peers, isEmpty);
  });

  test(
    'startup settling never restores an older larger peer catalog',
    () async {
      final fixture = await _loadFixture();
      final oldCatalog = _snapshotCopy(
        fixture,
        processId: 42,
        revision: 10,
        uptimeMs: 10000,
      );
      final currentCatalog = _snapshotCopy(
        fixture,
        processId: 42,
        revision: 11,
        uptimeMs: 10100,
        peers: const <dynamic>[],
      );
      final api = _SwitchingDiagnosticsApi(
        snapshot: currentCatalog,
        snapshots: [oldCatalog, currentCatalog],
      );
      final stores = await _makeStores(
        api,
        startupCatalogRefreshInterval: Duration.zero,
        startupCatalogRefreshTimeout: const Duration(seconds: 1),
      );
      addTearDown(stores.dispose);
      await stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(authToken: 'managed-token'),
      );

      await stores.statusStore.refreshUntilPeerCatalogSettled();

      expect(stores.statusStore.snapshot?.revision, 11);
      expect(stores.statusStore.snapshot?.peers, isEmpty);
    },
  );

  test('event revision triggers an immediate full snapshot refresh', () async {
    final fixture = await _loadFixture();
    final first = _snapshotCopy(
      fixture,
      processId: 42,
      revision: 1,
      uptimeMs: 100,
    );
    final second = _snapshotCopy(
      fixture,
      processId: 42,
      revision: 2,
      uptimeMs: 200,
      peers: const <dynamic>[],
    );
    final api = _SwitchingDiagnosticsApi(
      snapshot: second,
      snapshots: [first, second],
      events: const [
        EventsResponse(
          contractVersion: 1,
          processId: 42,
          revision: 2,
          oldestSeq: 2,
          events: [DiagnosticEvent(seq: 2, event: 'peer_left', atMs: 200)],
        ),
      ],
    );
    final stores = await _makeStores(api);
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    stores.statusStore.setAutoRefresh(enabled: true);
    await _waitUntil(() => api.statusFetchCount >= 2);

    expect(stores.statusStore.snapshot?.revision, 2);
    expect(stores.statusStore.snapshot?.peers, isEmpty);
    stores.statusStore.setAutoRefresh(enabled: false);
  });

  test(
    'event poll carries process identity and resets on daemon restart',
    () async {
      final fixture = await _loadFixture();
      final oldProcess = _snapshotCopy(
        fixture,
        processId: 42,
        revision: 1,
        uptimeMs: 5000,
      );
      final newProcess = _snapshotCopy(
        fixture,
        processId: 43,
        revision: 1,
        uptimeMs: 100,
        peers: const <dynamic>[],
      );
      final api = _SwitchingDiagnosticsApi(
        snapshot: newProcess,
        snapshots: [oldProcess, newProcess],
        events: const [
          EventsResponse(
            contractVersion: 1,
            processId: 43,
            revision: 1,
            oldestSeq: 1,
            resetRequired: true,
            events: [],
          ),
        ],
      );
      final stores = await _makeStores(api);
      addTearDown(stores.dispose);

      await stores.statusStore.refresh();
      stores.statusStore.setAutoRefresh(enabled: true);
      await _waitUntil(() => api.statusFetchCount >= 2);

      expect(api.eventProcessIds.first, 42);
      expect(api.eventCursors.first, 1);
      expect(stores.statusStore.snapshot?.processId, 43);
      expect(stores.statusStore.snapshot?.peers, isEmpty);
      stores.statusStore.setAutoRefresh(enabled: false);
    },
  );
}

DiagnosticsSnapshot _snapshotCopy(
  DiagnosticsSnapshot source, {
  required int processId,
  required int revision,
  required int uptimeMs,
  List<dynamic>? peers,
}) {
  final raw = Map<String, dynamic>.from(source.raw)
    ..['process_id'] = processId
    ..['revision'] = revision
    ..['captured_revision'] = revision
    ..['captured_at_ms'] = uptimeMs
    ..['peer_snapshot_stale'] = false
    ..['peer_snapshot_age_ms'] = 0
    ..['uptime_ms'] = uptimeMs;
  if (peers != null) raw['peers'] = peers;
  return DiagnosticsSnapshot.fromJson(raw);
}

Future<void> _waitUntil(bool Function() predicate) async {
  await (() async {
    while (!predicate()) {
      await Future<void>.delayed(const Duration(milliseconds: 10));
    }
  })().timeout(const Duration(seconds: 5));
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
  Duration routeVerificationInterval = Duration.zero,
  Duration startupCatalogRefreshInterval =
      StatusStore.defaultStartupCatalogRefreshInterval,
  Duration startupCatalogRefreshTimeout =
      StatusStore.defaultStartupCatalogRefreshTimeout,
}) async {
  final tempDir = await Directory.systemTemp.createTemp('p2wlan_status_store_');
  final settingsStore = SettingsStore(
    settingsFile: File('${tempDir.path}/settings.json'),
    tokenRepository: InMemorySecureTokenRepository(),
  );
  await settingsStore.load();
  final statusStore = StatusStore(
    settingsStore: settingsStore,
    diagnosticsApi: api,
    maxSnapshotAge: maxSnapshotAge,
    enableFreshnessTimer: true,
    routeVerificationInterval: routeVerificationInterval,
    startupCatalogRefreshInterval: startupCatalogRefreshInterval,
    startupCatalogRefreshTimeout: startupCatalogRefreshTimeout,
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
  _SwitchingDiagnosticsApi({
    required this.snapshot,
    this.oldHealth,
    List<DiagnosticsSnapshot>? snapshots,
    List<EventsResponse>? events,
  }) : snapshots = [...?snapshots],
       events = [...?events];

  final DiagnosticsSnapshot snapshot;
  final Completer<void>? oldHealth;
  final List<DiagnosticsSnapshot> snapshots;
  final List<EventsResponse> events;
  final pendingEvents = Completer<EventsResponse>();
  final oldHealthStarted = Completer<void>();
  final healthUrls = <String>[];
  final eventProcessIds = <int?>[];
  final eventCursors = <int>[];
  var verifyRoutesCount = 0;
  var statusFetchCount = 0;

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
  Future<DiagnosticsSnapshot> fetchStatus(String diagnosticsUrl) async {
    statusFetchCount += 1;
    return snapshots.isEmpty ? snapshot : snapshots.removeAt(0);
  }

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
  Future<EventsResponse> fetchEvents(
    String diagnosticsUrl, {
    int since = 0,
    int? processId,
    Duration timeout = const Duration(seconds: 30),
  }) async {
    eventProcessIds.add(processId);
    eventCursors.add(since);
    if (events.isNotEmpty) return events.removeAt(0);
    return pendingEvents.future;
  }

  @override
  Future<PeersPageResponse> fetchPeers(
    String diagnosticsUrl, {
    String? cursor,
    int limit = 100,
  }) async => throw UnimplementedError();

  @override
  Future<String> fetchLogTail(
    String diagnosticsUrl, {
    int lines = 120,
    int maxBytes = 262144,
  }) async => throw UnimplementedError();

  @override
  Future<RoutesResponse> verifyRoutes(String diagnosticsUrl) async {
    verifyRoutesCount += 1;
    return const RoutesResponse(
      contractVersion: 1,
      interfaceName: 'p2wlan',
      mtu: 1500,
      healthy: true,
      conflictCount: 0,
      entries: <RouteEntryResponse>[],
    );
  }

  @override
  Future<RouteRepairResponse> repairRoutes(String diagnosticsUrl) async =>
      throw UnimplementedError();

  @override
  void close() {}
}
