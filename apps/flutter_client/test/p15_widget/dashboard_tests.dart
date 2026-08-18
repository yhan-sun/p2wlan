part of '../p15_widget_test.dart';

void _registerDashboardTests() {
  testWidgets('Dashboard renders stopped state with start action', (
    tester,
  ) async {
    final stores = (await tester.runAsync(
      () => _makeStores(api: _FakeDiagnosticsApi(health: false)),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('P2WLAN is not running'), findsOneWidget);
    expect(
      find.text('Start P2WLAN to see your devices and connection status here.'),
      findsOneWidget,
    );
    expect(find.text('Virtual network stopped'), findsOneWidget);
    expect(find.text('Needs attention'), findsNothing);
    expect(find.byKey(const Key('dashboard-start-button')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-stop-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-refresh-button')), findsOneWidget);
    expect(find.text('Connection overview'), findsNothing);
    expect(find.text('Network environment'), findsNothing);
    expect(find.byKey(const Key('dashboard-connection-map')), findsNothing);
  });

  testWidgets('Dashboard shows stop only when daemon is reachable', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.text('Network type'), findsOneWidget);
    expect(find.textContaining('Restricted'), findsWidgets);
    expect(find.textContaining('Max probability'), findsNothing);
    expect(find.text('NAT probabilities'), findsNothing);
    expect(find.byIcon(Icons.info_outline_rounded), findsNothing);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-stop-button')), findsOneWidget);
  });

  testWidgets('StatusStore settles peer catalog after daemon start', (
    tester,
  ) async {
    final fullSnapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final partialSnapshot = _snapshotWithPeerCount(fullSnapshot, 1);
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshots: [partialSnapshot, fullSnapshot, fullSnapshot],
    );
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: api,
        startupCatalogRefreshInterval: Duration.zero,
        startupCatalogRefreshTimeout: const Duration(seconds: 1),
      ),
    ))!;
    addTearDown(stores.dispose);

    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(
          authToken: 'token',
          manualMode: false,
        ),
      ),
    );
    await tester.runAsync(stores.statusStore.startDaemon);

    expect(stores.statusStore.snapshot?.peers, hasLength(2));
    expect(api.statusFetchCount, greaterThanOrEqualTo(3));
  });

  testWidgets('Dashboard separates status endpoint errors from health', (
    tester,
  ) async {
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(
          health: true,
          statusError: const DiagnosticsApiException('status fixture failed'),
        ),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // Health is up but no snapshot: this is "unavailable", never "stopped".
    expect(find.textContaining('GET /status failed'), findsWidgets);
    expect(find.text('Virtual network stopped'), findsNothing);
    expect(find.text('Unavailable'), findsOneWidget);
    expect(find.text('Network status unavailable'), findsOneWidget);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-stop-button')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-refresh-button')), findsOneWidget);
    // No snapshot means no empty data regions.
    expect(find.text('Connection overview'), findsNothing);
    expect(find.text('Network environment'), findsNothing);
    expect(find.byKey(const Key('dashboard-connection-map')), findsNothing);
  });

  testWidgets('Dashboard keeps actions usable on narrow screens', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.byKey(const Key('dashboard-stop-button')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-refresh-button')), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Dashboard shows healthy network with peer connection states', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final snapshot = _snapshotWithPeers(base, _fourPeerFixtures());
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('10.20.0.5'), findsOneWidget);
    expect(find.text('Online devices'), findsOneWidget);
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.text('probing-phone'), findsOneWidget);
    expect(find.text('offline-printer'), findsOneWidget);
    expect(find.text('Direct'), findsNWidgets(2));
    expect(find.text('Relay'), findsNWidgets(3));
    expect(find.text('probing'), findsNWidgets(2));
    expect(find.text('Offline'), findsOneWidget);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-stop-button')), findsOneWidget);
  });

  testWidgets('Dashboard distinguishes verified latency from probe RTT', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final snapshot = _snapshotWithPeers(base, _fourPeerFixtures());
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('12 ms'), findsOneWidget);
    expect(find.text('43 ms'), findsOneWidget);
    expect(find.text('probe RTT 8 ms'), findsOneWidget);
    expect(find.text('8 ms'), findsNothing);
  });

  testWidgets('Dashboard shows exact hero connection counts', (tester) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final snapshot = _snapshotWithPeers(base, _fourPeerFixtures());
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // 1 direct + 1 relay + 1 probing + 1 offline: offline never counts as
    // online. Counts come from peer state, not from text occurrence counts.
    expect(_heroCount(tester, 'dashboard-count-online'), '3');
    expect(_heroCount(tester, 'dashboard-count-direct'), '1');
    expect(_heroCount(tester, 'dashboard-count-relay'), '1');
    expect(_heroCount(tester, 'dashboard-count-probing'), '1');
    expect(find.byKey(const Key('dashboard-count-probing')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-count-online')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-count-direct')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-count-relay')), findsOneWidget);
  });

  testWidgets('Dashboard hides daemon controls on mobile capabilities', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    const mobileCapabilities = PlatformCapabilities(
      canControlLocalDaemon: false,
      canRequestElevation: false,
      canVerifyRoutes: false,
      canRepairRoutes: false,
      canOpenLocalLogs: false,
      canCreateSupportBundle: false,
      canUseSystemTray: false,
      canActAsLocalVpnNode: false,
      canManageRemoteDevices: true,
    );
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: mobileCapabilities,
        ),
      ),
    );

    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-stop-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-refresh-button')), findsOneWidget);
  });

  testWidgets('Dashboard adapts layout across breakpoints', (tester) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();

    const sizes = [Size(390, 844), Size(700, 1000), Size(1280, 900)];
    for (final size in sizes) {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      await tester.pumpWidget(
        _TestApp(
          child: DashboardPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
          ),
        ),
      );
      await tester.pump();

      expect(tester.takeException(), isNull, reason: 'size $size');
      final map = find.byKey(const Key('dashboard-connection-map'));
      if (size.width >= 1024) {
        expect(map, findsOneWidget, reason: 'size $size');
      } else {
        expect(map, findsNothing, reason: 'size $size');
      }
    }
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });

  testWidgets('Connection map draws one branch per real peer (1..6)', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    for (var count = 1; count <= 6; count++) {
      final snapshot = _snapshotWithPeers(base, _peerFixturesForCount(count));
      final stores = (await tester.runAsync(
        () => _makeStores(
          api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
        ),
      ))!;
      addTearDown(stores.dispose);

      await stores.statusStore.refresh();
      await tester.pumpWidget(
        _TestApp(
          child: DashboardPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
          ),
        ),
      );
      await tester.pump();

      final lines = _mapLinePairs(
        tester,
        Size(120, _mapRowCount(count) * 80.0),
      );
      // One vertical trunk plus exactly one branch per real peer: no missing
      // branches and no dangling branches for empty rows.
      expect(
        lines.length,
        1 + count,
        reason: 'peers=$count (${_mapRowCount(count)} rows)',
      );
      final verticals = lines.where((line) => line.$1.dx == line.$2.dx);
      expect(verticals, hasLength(1), reason: 'peers=$count');
      final horizontals = lines.where((line) => line.$1.dy == line.$2.dy);
      expect(horizontals, hasLength(count), reason: 'peers=$count');
      for (final (a, b) in horizontals) {
        final touchesEdge =
            a.dx == 0 || a.dx == 120 || b.dx == 0 || b.dx == 120;
        final touchesTrunk = a.dx == 60 || b.dx == 60;
        expect(
          touchesEdge && touchesTrunk,
          isTrue,
          reason: 'peers=$count branch $a -> $b',
        );
      }
      expect(tester.takeException(), isNull, reason: 'peers=$count');
    }
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });
}

Map<String, dynamic> _peerJson({
  required String nodeId,
  required String deviceName,
  required String virtualIp,
  required bool online,
  required String state,
  String? activePath,
  required String? relayConfirmedEndpoint,
  int? relayConfirmedGeneration,
  required Map<String, dynamic> direct,
  required Map<String, dynamic> relay,
  Map<String, dynamic>? currentPathSelection,
}) {
  return {
    'node_id': nodeId,
    'device_name': deviceName,
    'app_version': '1.0.0',
    'virtual_ip': virtualIp,
    'endpoint': null,
    'nat_type': 'unknown',
    'online': online,
    'last_seen': 0,
    'state': state,
    'active_path': activePath,
    'direct_type': 'unknown',
    'is_relay': false,
    'bytes_sent': 0,
    'bytes_received': 0,
    'relay_server': null,
    'warning': null,
    'connected_for_ms': null,
    'direct': direct,
    'relay': relay,
    'current_path_selection': currentPathSelection,
    'relay_confirmed_endpoint': relayConfirmedEndpoint,
    'relay_confirmed_generation': relayConfirmedGeneration,
  };
}

Map<String, dynamic> _emptyPathHealth() => {
  'last_success_age_ms': null,
  'last_failure_age_ms': null,
  'consecutive_failures': 0,
  'last_error': null,
  'last_error_code': null,
  'latency_ms': null,
  'rtt_ewma_ms': null,
};

/// Four peers matching the real model rules: a verified direct peer, a
/// verified relay peer (matching encrypted relay ACK), a direct trial still
/// probing (candidate RTT only), and an offline peer.
List<Map<String, dynamic>> _fourPeerFixtures() {
  final directPeer = _peerJson(
    nodeId: 'node-direct',
    deviceName: 'direct-laptop',
    virtualIp: '10.20.0.11',
    online: true,
    state: 'direct',
    activePath: 'direct',
    relayConfirmedEndpoint: null,
    direct: {
      'last_success_age_ms': 100,
      'last_failure_age_ms': null,
      'consecutive_failures': 0,
      'last_error': null,
      'last_error_code': null,
      'latency_ms': 12,
      'rtt_ewma_ms': null,
    },
    relay: _emptyPathHealth(),
    currentPathSelection: {
      'path': 'direct',
      'direct_endpoint': '198.51.100.21:61111',
      'reason_code': 'path_direct_confirmed',
      'reason': 'public UDP pair confirmed',
      'direct_confirmed': true,
      'relay_hedged': false,
    },
  );
  final relayPeer = _peerJson(
    nodeId: 'node-relay',
    deviceName: 'relay-nas',
    virtualIp: '10.20.0.12',
    online: true,
    state: 'relay',
    activePath: 'relay',
    relayConfirmedEndpoint: '203.0.113.10:18081',
    relayConfirmedGeneration: 5,
    direct: _emptyPathHealth(),
    relay: {
      'last_success_age_ms': 300,
      'last_failure_age_ms': null,
      'consecutive_failures': 0,
      'last_error': null,
      'last_error_code': null,
      'latency_ms': 43,
      'rtt_ewma_ms': null,
    },
    currentPathSelection: {
      'path': 'relay',
      'direct_endpoint': null,
      'reason_code': 'path_relay_fallback',
      'reason': 'direct path unavailable; relay confirmed',
      'direct_confirmed': false,
      'relay_hedged': false,
    },
  );
  final probingPeer = _peerJson(
    nodeId: 'node-probing',
    deviceName: 'probing-phone',
    virtualIp: '10.20.0.13',
    online: true,
    state: 'connecting',
    activePath: null,
    relayConfirmedEndpoint: null,
    direct: {
      'last_success_age_ms': null,
      'last_failure_age_ms': null,
      'consecutive_failures': 0,
      'last_error': null,
      'last_error_code': null,
      'latency_ms': 8,
      'rtt_ewma_ms': null,
    },
    relay: _emptyPathHealth(),
    currentPathSelection: {
      'path': 'direct',
      'direct_endpoint': '198.51.100.22:61112',
      'reason_code': 'path_direct_trial',
      'reason': 'candidate probe succeeded',
      'direct_confirmed': false,
      'relay_hedged': false,
    },
  );
  final offlinePeer = _peerJson(
    nodeId: 'node-offline',
    deviceName: 'offline-printer',
    virtualIp: '10.20.0.14',
    online: false,
    state: 'unknown',
    activePath: null,
    relayConfirmedEndpoint: null,
    direct: _emptyPathHealth(),
    relay: _emptyPathHealth(),
  );
  return [directPeer, relayPeer, probingPeer, offlinePeer];
}

/// Five peers (4 fixtures + one extra verified direct peer) to exercise map
/// rows with asymmetric left/right occupancy (3 left, 2 right).
List<Map<String, dynamic>> _fivePeerFixtures() {
  return [
    ..._fourPeerFixtures(),
    _peerJson(
      nodeId: 'node-direct2',
      deviceName: 'direct-desktop',
      virtualIp: '10.20.0.15',
      online: true,
      state: 'direct',
      activePath: 'direct',
      relayConfirmedEndpoint: null,
      direct: {
        'last_success_age_ms': 60,
        'last_failure_age_ms': null,
        'consecutive_failures': 0,
        'last_error': null,
        'last_error_code': null,
        'latency_ms': 18,
        'rtt_ewma_ms': null,
      },
      relay: _emptyPathHealth(),
      currentPathSelection: {
        'path': 'direct',
        'direct_endpoint': '198.51.100.23:61113',
        'reason_code': 'path_direct_confirmed',
        'reason': 'public UDP pair confirmed',
        'direct_confirmed': true,
        'relay_hedged': false,
      },
    ),
  ];
}

/// A pool of distinct peers used to build snapshots with any 1..6 peer count.
/// First four come from [_fourPeerFixtures]; the rest are distinct verified
/// paths (direct / relay) matching the real model rules.
List<Map<String, dynamic>> _peerFixturesForCount(int count) {
  assert(count >= 1 && count <= 6);
  final pool = <Map<String, dynamic>>[
    ..._fourPeerFixtures(),
    ..._fivePeerFixtures().skip(4),
    _peerJson(
      nodeId: 'node-relay2',
      deviceName: 'relay-server2',
      virtualIp: '10.20.0.16',
      online: true,
      state: 'relay',
      activePath: 'relay',
      relayConfirmedEndpoint: '203.0.113.11:18082',
      relayConfirmedGeneration: 7,
      direct: _emptyPathHealth(),
      relay: {
        'last_success_age_ms': 250,
        'last_failure_age_ms': null,
        'consecutive_failures': 0,
        'last_error': null,
        'last_error_code': null,
        'latency_ms': 55,
        'rtt_ewma_ms': null,
      },
      currentPathSelection: {
        'path': 'relay',
        'direct_endpoint': null,
        'reason_code': 'path_relay_fallback',
        'reason': 'direct path unavailable; relay confirmed',
        'direct_confirmed': false,
        'relay_hedged': false,
      },
    ),
  ];
  return pool.take(count).toList();
}

/// Number of map rows for a peer count (peers are split left / right).
int _mapRowCount(int peerCount) => (peerCount + 1) ~/ 2;

String _heroCount(WidgetTester tester, String key) {
  final text = tester.widget<Text>(
    find
        .descendant(of: find.byKey(Key(key)), matching: find.byType(Text))
        .first,
  );
  return text.data!;
}

/// Paints the connection-map painter from the widget tree onto a recording
/// canvas and returns the drawn line segments as offset pairs.
Set<(Offset, Offset)> _mapLinePairs(WidgetTester tester, Size paintSize) {
  final customPaint = tester.widget<CustomPaint>(
    find.descendant(
      of: find.byKey(const Key('dashboard-connection-map')),
      matching: find.byType(CustomPaint),
    ),
  );
  final canvas = TestRecordingCanvas();
  customPaint.painter!.paint(canvas, paintSize);
  final lines = <(Offset, Offset)>{};
  for (final recorded in canvas.invocations) {
    if (recorded.invocation.memberName != #drawLine) continue;
    final args = recorded.invocation.positionalArguments;
    lines.add((args[0] as Offset, args[1] as Offset));
  }
  return lines;
}

DiagnosticsSnapshot _snapshotWithPeers(
  DiagnosticsSnapshot base,
  List<Map<String, dynamic>> peers,
) {
  final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
  raw['peers'] = peers;
  (raw['stats'] as Map<String, dynamic>)['total_peers'] = peers.length;
  raw['virtual_ip'] = '10.20.0.5';
  return DiagnosticsSnapshot.fromJson(raw);
}
