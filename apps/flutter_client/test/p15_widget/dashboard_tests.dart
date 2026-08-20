part of '../p15_widget_test.dart';

void _registerDashboardTests() {
  testWidgets('Home renders stopped state with start action', (tester) async {
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
    expect(find.text('Start it to join the virtual network.'), findsOneWidget);
    expect(find.text('Not running'), findsOneWidget);
    expect(find.text('Check issues'), findsNothing);
    expect(find.byKey(const Key('dashboard-start-button')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-stop-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-refresh-button')), findsOneWidget);
    // No snapshot: no data regions at all.
    expect(find.text('Online devices'), findsNothing);
    expect(find.text('Network components'), findsNothing);
  });

  testWidgets('Home shows healthy network from a real fixture snapshot', (
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

    // Healthy hero: status + Virtual IP first.
    expect(find.text('Network status'), findsOneWidget);
    expect(find.text('Normal'), findsWidgets);
    expect(find.text('Your device is on the P2WLAN network'), findsOneWidget);
    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.text('Virtual IP address'), findsOneWidget);
    expect(find.textContaining('Network ID'), findsOneWidget);

    // Key metrics from peer state: online / direct / relay.
    expect(_heroCount(tester, 'dashboard-count-online'), '2');
    expect(_heroCount(tester, 'dashboard-count-direct'), '1');
    expect(_heroCount(tester, 'dashboard-count-relay'), '1');

    // Device preview section is titled "Devices" (it may show offline peers).
    expect(find.text('Devices'), findsOneWidget);
    expect(find.text('Online devices'), findsWidgets);
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.text('10.20.0.11'), findsOneWidget);

    // Healthy hero: no duplicate inline refresh — the shell owns refresh.
    expect(find.byKey(const Key('dashboard-refresh-button')), findsNothing);

    // Network components: only rows the fixture can judge. The fixture has no
    // ready_phase, so the Overlay route row is honestly omitted.
    expect(find.text('Control server'), findsOneWidget);
    expect(find.text('Device connectivity'), findsOneWidget);
    expect(find.text('2 / 2'), findsOneWidget);
    expect(find.text('Overlay route'), findsNothing);

    // Healthy → no issue CTA.
    expect(find.text('Check issues'), findsNothing);
  });

  testWidgets('Home keeps technical noise off the default page', (
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

    for (final technical in [
      'UDP',
      'Network type',
      'Request duration',
      'Last refresh',
      'Snapshot',
      'Endpoint state',
      'Peer ID',
      'MTU',
      'NAT probabilities',
    ]) {
      expect(
        find.text(technical),
        findsNothing,
        reason: 'technical field "$technical" must not appear on Home',
      );
    }
  });

  testWidgets('Home shows last-known data with a stale note', (tester) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
        enableFreshnessTimer: true,
        maxSnapshotAge: const Duration(milliseconds: 50),
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
    await tester.pump(const Duration(milliseconds: 120));

    // Last-known data kept, stale note shown, refresh available.
    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.text('Data may be out of date'), findsOneWidget);
    expect(find.byKey(const Key('home-stale-refresh')), findsOneWidget);
    expect(find.text('Stale'), findsOneWidget);
    // Staleness is not an issue banner.
    expect(find.text('Check issues'), findsNothing);
  });

  testWidgets('Home separates status endpoint errors from health', (
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

    // Health is up but no snapshot: unavailable, never stopped.
    expect(find.text('Cannot reach P2WLAN'), findsOneWidget);
    expect(
      find.text('The local network service is currently unavailable.'),
      findsOneWidget,
    );
    expect(find.text('Not running'), findsNothing);
    expect(find.text('Unavailable'), findsOneWidget);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-check-button')), findsOneWidget);
    expect(find.text('Online devices'), findsNothing);
  });

  testWidgets('Home shows peer connection states with real latency', (
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

    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.text('probing-phone'), findsOneWidget);
    expect(find.text('offline-printer'), findsOneWidget);
    // Metric labels add one more occurrence each.
    expect(find.text('Direct'), findsNWidgets(2));
    expect(find.text('Relay'), findsNWidgets(2));
    expect(find.text('probing'), findsOneWidget);
    expect(find.text('Offline'), findsOneWidget);
    // Verified latency, relay latency, and explicitly labeled probe RTT.
    expect(find.text('12 ms'), findsOneWidget);
    expect(find.text('43 ms'), findsOneWidget);
    expect(find.text('probe RTT 8 ms'), findsOneWidget);
    expect(find.text('8 ms'), findsNothing);
  });

  testWidgets('Home shows exact hero connection counts', (tester) async {
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

    // 1 direct + 1 relay + 1 probing = 3 online; offline never counts.
    // Probing is deliberately not a fourth metric.
    expect(_heroCount(tester, 'dashboard-count-online'), '3');
    expect(_heroCount(tester, 'dashboard-count-direct'), '1');
    expect(_heroCount(tester, 'dashboard-count-relay'), '1');
    expect(find.byKey(const Key('dashboard-count-probing')), findsNothing);
  });

  testWidgets('Home previews at most five devices', (tester) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final snapshot = _snapshotWithPeers(base, _peerFixturesForCount(6));
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

    // Attention first, then relay, direct, offline last — the offline peer is
    // the one pushed past the preview limit.
    expect(find.text('probing-phone'), findsOneWidget);
    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.text('relay-server2'), findsOneWidget);
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('direct-desktop'), findsOneWidget);
    expect(find.text('offline-printer'), findsNothing);
  });

  testWidgets('Home handles a healthy network with no peers', (tester) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final snapshot = _snapshotWithPeerCount(base, 0);
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

    expect(find.text('No other devices online'), findsOneWidget);
    expect(
      find.text('Devices appear here when they come online.'),
      findsOneWidget,
    );
    expect(find.text('0 / 0'), findsOneWidget);
    expect(_heroCount(tester, 'dashboard-count-online'), '0');
  });

  testWidgets('Home shows an issue banner with troubleshooting CTA', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
    (raw['health'] as Map<String, dynamic>)['status'] = 'degraded';
    (raw['health'] as Map<String, dynamic>)['reason'] =
        'Overlay route or connection state needs review';
    final snapshot = DiagnosticsSnapshot.fromJson(raw);
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    var opened = false;
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          onOpenTroubleshooting: () => opened = true,
        ),
      ),
    );

    expect(find.text('Network issue found'), findsOneWidget);
    expect(
      find.text('Overlay route or connection state needs review'),
      findsOneWidget,
    );
    expect(find.text('Check issues'), findsOneWidget);
    expect(find.text('Degraded'), findsOneWidget);

    await tester.tap(find.byKey(const Key('home-check-issues')));
    expect(opened, isTrue);
  });

  testWidgets('Shell: View all devices opens the Devices section', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1280, 800);
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
        child: P2WlanShell(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.byType(DashboardPage), findsOneWidget);
    expect(find.byType(DesktopSidebar), findsOneWidget);

    await tester.tap(find.byKey(const Key('home-view-all-devices')));
    await tester.pumpAndSettle();

    expect(find.byType(NodesPage), findsOneWidget);
    expect(find.byType(DashboardPage), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Shell: issue CTA opens Troubleshooting on mobile', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
    (raw['health'] as Map<String, dynamic>)['status'] = 'degraded';
    (raw['health'] as Map<String, dynamic>)['reason'] =
        'Overlay route or connection state needs review';
    final snapshot = DiagnosticsSnapshot.fromJson(raw);
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: P2WlanShell(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('Check issues'), findsOneWidget);
    expect(
      find.descendant(
        of: find.byType(NavigationBar),
        matching: find.byType(NavigationDestination),
      ),
      findsNWidgets(3),
    );

    await tester.tap(find.byKey(const Key('home-check-issues')));
    await tester.pumpAndSettle();

    expect(find.byType(DiagnosticsPage), findsOneWidget);
    expect(
      find.descendant(
        of: find.byType(NavigationBar),
        matching: find.byType(NavigationDestination),
      ),
      findsNWidgets(3),
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('Home keeps actions usable on narrow screens', (tester) async {
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

    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.byKey(const Key('dashboard-stop-button')), findsOneWidget);
    // Healthy: refresh stays in the shell; the hero does not repeat it.
    expect(find.byKey(const Key('dashboard-refresh-button')), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Home hides daemon controls on mobile capabilities', (
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
  });

  testWidgets('Home with no local daemon control never offers Start', (
    tester,
  ) async {
    final stores = (await tester.runAsync(
      () => _makeStores(api: _FakeDiagnosticsApi(health: false)),
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

    expect(find.text('Cannot reach P2WLAN'), findsOneWidget);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.text('Start P2WLAN'), findsNothing);
    expect(find.byKey(const Key('dashboard-check-button')), findsOneWidget);
  });

  testWidgets('Home adapts layout across breakpoints', (tester) async {
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
      expect(find.text('10.20.0.10'), findsOneWidget, reason: 'size $size');
      expect(find.text('direct-laptop'), findsOneWidget, reason: 'size $size');
      expect(find.text('Control server'), findsOneWidget, reason: 'size $size');
      expect(
        find.text('Network components'),
        findsOneWidget,
        reason: 'size $size',
      );
    }
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });

  testWidgets('Home dark theme renders the full healthy page', (tester) async {
    tester.view.physicalSize = const Size(1280, 900);
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
      _DesignSystemHost(
        dark: true,
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('Control server'), findsOneWidget);
    expect(find.text('Network components'), findsOneWidget);
    expect(tester.takeException(), isNull);
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

/// Five peers (4 fixtures + one extra verified direct peer).
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

String _heroCount(WidgetTester tester, String key) {
  final text = tester.widget<Text>(
    find
        .descendant(of: find.byKey(Key(key)), matching: find.byType(Text))
        .first,
  );
  return text.data!;
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
