import 'dart:async';
import 'dart:convert';
import 'dart:io';

import 'package:flutter/widgets.dart' show AppLifecycleState;
import 'package:flutter_test/flutter_test.dart';
import 'package:p2wlan_flutter_client/core/api/diagnostics_api.dart';
import 'package:p2wlan_flutter_client/core/models/diagnostics_models.dart';
import 'package:p2wlan_flutter_client/core/security/secure_token_repository.dart';
import 'package:p2wlan_flutter_client/core/state/settings_store.dart';
import 'package:p2wlan_flutter_client/core/state/status_store.dart';

void main() {
  test('default polling cadence is 1s foreground and 10s background', () {
    expect(
      StatusStore.defaultActivePollingInterval,
      const Duration(seconds: 1),
    );
    expect(
      StatusStore.defaultBackgroundPollingInterval,
      const Duration(seconds: 10),
    );
    expect(
      StatusStore.defaultRouteVerificationInterval,
      const Duration(seconds: 10),
    );
    expect(
      StatusStore.defaultMetricsUpdateInterval,
      const Duration(seconds: 1),
    );
  });

  test(
    'stable peer order keeps first-seen rows and appends new peers',
    () async {
      final fixture = await _loadFixture();
      final stores = await _makeStores(DiagnosticsApi());
      addTearDown(stores.dispose);

      final initial = stores.statusStore.stablePeerOrder(fixture.peers);
      final reordered = stores.statusStore.stablePeerOrder(
        fixture.peers.reversed,
      );

      expect(
        reordered.map((peer) => peer.nodeId),
        initial.map((peer) => peer.nodeId),
      );

      final raw = jsonDecode(jsonEncode(fixture.raw)) as Map<String, dynamic>;
      final peers = [
        for (final item in raw['peers'] as List<dynamic>)
          Map<String, dynamic>.from(item as Map),
      ];
      peers.add(
        Map<String, dynamic>.from(peers.first)
          ..['node_id'] = 'node-appended'
          ..['device_name'] = 'appended-device'
          ..['virtual_ip'] = '10.20.0.250',
      );
      final withNewPeer = DiagnosticsSnapshot.fromJson(raw..['peers'] = peers);
      final extended = stores.statusStore.stablePeerOrder(
        withNewPeer.peers.reversed,
      );

      expect(extended.last.nodeId, 'node-appended');
    },
  );

  test('stable peer order puts online peers first and moves reconnected peers to the end', () async {
    final fixture = await _loadFixture();
    final stores = await _makeStores(DiagnosticsApi());
    addTearDown(stores.dispose);

    final initial = stores.statusStore.stablePeerOrder(fixture.peers);
    final firstOnline = initial.first;
    expect(firstOnline.online, isTrue);

    final offlineRaw =
        jsonDecode(jsonEncode(fixture.raw)) as Map<String, dynamic>;
    final offlinePeers = [
      for (final item in offlineRaw['peers'] as List<dynamic>)
        Map<String, dynamic>.from(item as Map),
    ];
    final firstOffline = offlinePeers.firstWhere(
      (item) => item['node_id'] == firstOnline.nodeId,
    );
    firstOffline
      ..['online'] = false
      ..['state'] = 'unknown'
      ..['active_path'] = null
      ..['current_path_selection'] = null;
    final offlineSnapshot = DiagnosticsSnapshot.fromJson(
      offlineRaw..['peers'] = offlinePeers,
    );
    final whileOffline = stores.statusStore.stablePeerOrder(
      offlineSnapshot.peers,
    );
    expect(whileOffline.last.nodeId, firstOnline.nodeId);

    final restoredRaw =
        jsonDecode(jsonEncode(fixture.raw)) as Map<String, dynamic>;
    final restoredPeers = [
      for (final item in restoredRaw['peers'] as List<dynamic>)
        Map<String, dynamic>.from(item as Map),
    ];
    final restored = stores.statusStore.stablePeerOrder(
      DiagnosticsSnapshot.fromJson(restoredRaw..['peers'] = restoredPeers)
          .peers,
    );
    final restoredOnline = restored
        .where((peer) => peer.online && peer.path != 'offline')
        .toList();
    expect(restoredOnline.last.nodeId, firstOnline.nodeId);
    expect(
      restored
          .skipWhile((peer) => peer.online && peer.path != 'offline')
          .every((peer) => !peer.online || peer.path == 'offline'),
      isTrue,
    );
  });

  test('automatic refresh stays silent while work is in flight', () async {
    final fixture = await _loadFixture();
    final health = Completer<void>();
    final api = _SwitchingDiagnosticsApi(snapshot: fixture, oldHealth: health);
    final stores = await _makeStores(api);
    addTearDown(stores.dispose);

    final refresh = stores.statusStore.refresh(silent: true);
    await api.oldHealthStarted.future;

    expect(stores.statusStore.refreshing, isTrue);
    expect(stores.statusStore.refreshActivityVisible, isFalse);

    health.complete();
    await refresh;
    expect(stores.statusStore.refreshing, isFalse);
    expect(stores.statusStore.refreshActivityVisible, isFalse);
  });

  test('explicit refresh exposes progress while work is in flight', () async {
    final fixture = await _loadFixture();
    final health = Completer<void>();
    final api = _SwitchingDiagnosticsApi(snapshot: fixture, oldHealth: health);
    final stores = await _makeStores(api);
    addTearDown(stores.dispose);

    final refresh = stores.statusStore.refresh();
    await api.oldHealthStarted.future;

    expect(stores.statusStore.refreshing, isTrue);
    expect(stores.statusStore.refreshActivityVisible, isTrue);

    health.complete();
    await refresh;
    expect(stores.statusStore.refreshActivityVisible, isFalse);
  });

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

  test(
    'directional peer throughput exposes upload and download samples',
    () async {
      final fixture = await _loadFixture();
      final peerId = fixture.peers.first.nodeId;
      final first = _snapshotWithPeerCounters(
        fixture,
        peerId: peerId,
        bytesSent: 1000,
        bytesReceived: 2000,
      );
      final second = _snapshotWithPeerCounters(
        fixture,
        peerId: peerId,
        bytesSent: 9000,
        bytesReceived: 14000,
      );
      final api = _SwitchingDiagnosticsApi(
        snapshot: second,
        snapshots: [first, second],
      );
      final stores = await _makeStores(api);
      addTearDown(stores.dispose);

      await stores.statusStore.refresh();
      await Future<void>.delayed(const Duration(milliseconds: 10));
      await stores.statusStore.refresh();

      final rate = stores.statusStore.peerDirectionalTransferRates[peerId];
      expect(rate, isNotNull);
      expect(rate!.uploadBytesPerSecond, greaterThan(0));
      expect(rate.downloadBytesPerSecond, greaterThan(0));
      expect(
        stores.statusStore.peerTransferRatesBytesPerSecond[peerId],
        rate.uploadBytesPerSecond + rate.downloadBytesPerSecond,
      );
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

  test('rejects a late response from a retired daemon process', () async {
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
    final delayedOldProcess = _snapshotCopy(
      fixture,
      processId: 42,
      revision: 11,
      uptimeMs: 11000,
    );
    final api = _SwitchingDiagnosticsApi(
      snapshot: newProcess,
      snapshots: [oldProcess, newProcess, delayedOldProcess],
    );
    final stores = await _makeStores(api);
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
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

  test('startup catalog settling has an explicit transient state', () async {
    final fixture = await _loadFixture();
    final health = Completer<void>();
    final api = _SwitchingDiagnosticsApi(snapshot: fixture, oldHealth: health);
    final stores = await _makeStores(
      api,
      startupCatalogRefreshInterval: Duration.zero,
      startupCatalogRefreshTimeout: const Duration(milliseconds: 1),
    );
    addTearDown(stores.dispose);
    await stores.settingsStore.updateSettings(
      stores.settingsStore.settings.copyWith(authToken: 'managed-token'),
    );

    final settling = stores.statusStore.refreshUntilPeerCatalogSettled(
      silent: true,
    );
    await api.oldHealthStarted.future;
    expect(stores.statusStore.startupCatalogSettling, isTrue);

    health.complete();
    await settling.timeout(const Duration(seconds: 1));
    expect(stores.statusStore.startupCatalogSettling, isFalse);
  });

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
    'mobile lifecycle stops background event polling and revalidates on resume',
    () async {
      final fixture = await _loadFixture();
      final api = _LifecycleDiagnosticsApi(snapshot: fixture);
      final stores = await _makeStores(api);
      addTearDown(stores.dispose);

      await stores.statusStore.refresh();
      stores.statusStore.setAutoRefresh(enabled: true);
      await _waitUntil(() => api.eventRequests.length == 1);
      final statusCountBeforePause = api.statusFetchCount;

      stores.statusStore.updateAppLifecycleState(AppLifecycleState.paused);
      expect(stores.statusStore.appInForeground, isFalse);
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(
        api.eventRequests,
        hasLength(1),
        reason: 'backgrounding must not create another long poll',
      );

      // Resume while the pre-suspend request is still pending. The new event
      // loop must not wait for that stale network future to reach its timeout.
      stores.statusStore.updateAppLifecycleState(AppLifecycleState.resumed);
      await _waitUntil(() => api.statusFetchCount > statusCountBeforePause);
      await _waitUntil(() => api.eventRequests.length == 2);
      expect(stores.statusStore.appInForeground, isTrue);
      expect(
        api.eventProcessIds.last,
        fixture.processId,
        reason:
            'resume must rebuild the event cursor from the refreshed process',
      );

      // A late completion from the suspended network epoch is ignored and
      // must not spawn a third request beside the current resumed loop.
      api.completeEventRequest(0, fixture);
      await Future<void>.delayed(const Duration(milliseconds: 50));
      expect(api.eventRequests, hasLength(2));

      stores.statusStore.setAutoRefresh(enabled: false);
      api.completeEventRequest(1, fixture);
    },
  );

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

  test('disposed store cannot restart polling', () async {
    final fixture = await _loadFixture();
    final api = _SwitchingDiagnosticsApi(snapshot: fixture);
    final stores = await _makeStores(api);
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    final statusCount = api.statusFetchCount;
    stores.statusStore.dispose();

    stores.statusStore.setAutoRefresh(enabled: true, refreshImmediately: true);
    await stores.statusStore.refresh();
    await Future<void>.delayed(const Duration(milliseconds: 20));

    expect(api.statusFetchCount, statusCount);
  });
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

DiagnosticsSnapshot _snapshotWithPeerCounters(
  DiagnosticsSnapshot source, {
  required String peerId,
  required int bytesSent,
  required int bytesReceived,
}) {
  final raw = jsonDecode(jsonEncode(source.raw)) as Map<String, dynamic>;
  final peers = raw['peers'] as List<dynamic>;
  for (final value in peers) {
    final peer = value as Map<String, dynamic>;
    if (peer['node_id'] == peerId) {
      peer['bytes_sent'] = bytesSent;
      peer['bytes_received'] = bytesReceived;
      break;
    }
  }
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
  final raw = jsonDecode(
    await File('test/fixtures/status_connected.json').readAsString(),
  ) as Map<String, dynamic>;
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

class _LifecycleDiagnosticsApi extends _SwitchingDiagnosticsApi {
  _LifecycleDiagnosticsApi({required super.snapshot});

  final eventRequests = <Completer<EventsResponse>>[];

  @override
  Future<EventsResponse> fetchEvents(
    String diagnosticsUrl, {
    int since = 0,
    int? processId,
    Duration timeout = const Duration(seconds: 30),
  }) {
    eventProcessIds.add(processId);
    eventCursors.add(since);
    final request = Completer<EventsResponse>();
    eventRequests.add(request);
    return request.future;
  }

  void completeEventRequest(int index, DiagnosticsSnapshot snapshot) {
    final request = eventRequests[index];
    if (request.isCompleted) return;
    request.complete(
      EventsResponse(
        contractVersion: 1,
        processId: snapshot.processId,
        revision: snapshot.revision,
        oldestSeq: snapshot.revision,
        resetRequired: false,
        events: const [],
      ),
    );
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
