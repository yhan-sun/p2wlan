part of '../p15_widget_test.dart';

void _registerDashboardTests() {
  test('formats peer throughput in K/S, M/S, and G/S', () {
    expect(formatTransferRate(null), '—');
    expect(formatTransferRate(1024), '1 K/S');
    expect(formatTransferRate(1024 * 1024), '1 M/S');
    expect(formatTransferRate(1024 * 1024 * 1024), '1 G/S');
  });

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
    expect(find.byKey(const Key('dashboard-refresh-button')), findsNothing);
    // No snapshot: no data regions at all.
    expect(find.text('Online devices'), findsNothing);
    expect(find.text('Network components'), findsNothing);
  });

  testWidgets(
    'Home keeps initial and periodic status detection in the background',
    (tester) async {
      final api = _ControllableOfflineDiagnosticsApi();
      final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
      addTearDown(stores.dispose);

      final initialHealth = api.pauseNextHealth();
      final initialRefresh = stores.statusStore.refresh(silent: true);
      await tester.pumpWidget(
        _TestApp(
          child: DashboardPage(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
          ),
        ),
      );

      // Detection starts immediately, but it is background state: Home keeps
      // its stable default and never presents a foreground loading task.
      expect(stores.statusStore.refreshing, isTrue);
      expect(stores.statusStore.refreshActivityVisible, isFalse);
      expect(find.text('Fetching network status…'), findsNothing);
      expect(find.text('P2WLAN is not running'), findsOneWidget);
      expect(find.byKey(const Key('dashboard-start-button')), findsOneWidget);
      expect(find.byType(CircularProgressIndicator), findsNothing);
      expect(
        tester
            .widget<FilledButton>(
              find.byKey(const Key('dashboard-start-button')),
            )
            .onPressed,
        isNull,
      );

      initialHealth.complete(false);
      await initialRefresh;
      await tester.pump();
      expect(find.text('P2WLAN is not running'), findsOneWidget);
      expect(find.byKey(const Key('dashboard-start-button')), findsOneWidget);
      expect(
        tester
            .widget<FilledButton>(
              find.byKey(const Key('dashboard-start-button')),
            )
            .onPressed,
        isNotNull,
      );

      // A periodic poll must not send the confirmed stopped UI back to the
      // loading state while its health request is in flight.
      final nextHealth = api.pauseNextHealth();
      final periodicRefresh = stores.statusStore.refresh(silent: true);
      await tester.pump();
      expect(stores.statusStore.refreshing, isTrue);
      expect(stores.statusStore.refreshActivityVisible, isFalse);
      expect(find.text('Fetching network status…'), findsNothing);
      expect(find.text('P2WLAN is not running'), findsOneWidget);
      expect(find.byKey(const Key('dashboard-start-button')), findsOneWidget);
      expect(find.text('Refreshing...'), findsNothing);
      expect(find.byKey(const Key('dashboard-refresh-button')), findsNothing);
      expect(find.byKey(const Key('dashboard-check-button')), findsNothing);
      expect(find.byType(CircularProgressIndicator), findsNothing);
      expect(
        tester
            .widget<FilledButton>(
              find.byKey(const Key('dashboard-start-button')),
            )
            .onPressed,
        isNotNull,
      );

      nextHealth.complete(false);
      await periodicRefresh;
      await tester.pump();
      expect(find.text('P2WLAN is not running'), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );

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

    // Healthy hero: status + Virtual IP first, with no redundant identity
    // sentence or network-id line.
    expect(find.text('Network status'), findsOneWidget);
    expect(find.text('Normal'), findsWidgets);
    expect(find.text('Your device is on the P2WLAN network'), findsNothing);
    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.text('Virtual IP address'), findsOneWidget);
    expect(find.textContaining('Network ID'), findsNothing);

    // Key metrics from peer state plus the local NAT profile.
    expect(_heroCount(tester, 'dashboard-count-online'), '2');
    expect(_heroCount(tester, 'dashboard-count-direct'), '1');
    expect(_heroCount(tester, 'dashboard-count-relay'), '1');
    expect(_heroCount(tester, 'dashboard-nat-type'), 'Restricted');

    // Device preview section is titled "Devices" and contains connected peers.
    expect(find.text('Devices'), findsOneWidget);
    expect(find.text('Online devices'), findsWidgets);
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.text('10.20.0.11'), findsOneWidget);
    expect(find.text('offline-printer'), findsNothing);

    // Healthy hero: no duplicate inline refresh; status polling is automatic.
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

  testWidgets('Home keeps mapping evidence while NAT subtype is pending', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
    raw['nat_profile'] = {
      'mapping_behavior': 'endpoint_independent',
      'filtering_behavior': 'unknown',
      'public_endpoint': '198.51.100.20:62000',
      'confidence': 90,
    };
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
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(_heroCount(tester, 'dashboard-nat-type'), 'Endpoint independent');
    expect(find.text('Unknown'), findsNothing);
  });

  testWidgets('Home distinguishes API reachability from online lease health', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final raw = jsonDecode(jsonEncode(base.raw)) as Map<String, dynamic>;
    final health = raw['health'] as Map<String, dynamic>;
    health
      ..['status'] = 'degraded'
      ..['control_connected'] = false
      ..['control_api_reachable'] = true
      ..['device_lease_healthy'] = false
      ..['last_device_lease_success_secs_ago'] = 12;
    raw['ready_phase'] = 'connecting_control';
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
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('Degraded'), findsOneWidget);
    expect(find.text('Online lease refresh failed'), findsOneWidget);
    expect(
      find.text(
        "This device's server-side online lease could not be refreshed; peers may now see it as offline.",
      ),
      findsOneWidget,
    );
    expect(find.text('Control server'), findsOneWidget);
  });

  testWidgets('Home never counts an offline peer with a stale active path', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stale = _peerJson(
      nodeId: 'offline-stale-direct',
      deviceName: 'offline-stale-direct',
      virtualIp: '10.20.0.99',
      online: false,
      state: 'direct',
      activePath: 'direct',
      relayConfirmedEndpoint: null,
      direct: {'latency_ms': 1},
      relay: _emptyPathHealth(),
    );
    final snapshot = _snapshotWithPeers(base, [stale]);
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

    expect(_heroCount(tester, 'dashboard-count-online'), '0');
    expect(_heroCount(tester, 'dashboard-count-direct'), '0');
    expect(_heroCount(tester, 'dashboard-count-relay'), '0');
    expect(find.text('offline-stale-direct'), findsNothing);
  });

  testWidgets('Home counts an online peer without a verified path as probing', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final pending = _peerJson(
      nodeId: 'online-no-path',
      deviceName: 'online-no-path',
      virtualIp: '10.20.0.98',
      online: true,
      state: 'idle',
      activePath: null,
      relayConfirmedEndpoint: null,
      direct: _emptyPathHealth(),
      relay: _emptyPathHealth(),
    );
    final snapshot = _snapshotWithPeers(base, [pending]);
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

    expect(_heroCount(tester, 'dashboard-count-online'), '1');
    expect(_heroCount(tester, 'dashboard-count-direct'), '0');
    expect(_heroCount(tester, 'dashboard-count-relay'), '0');
    expect(find.text('online-no-path'), findsOneWidget);
    expect(find.text('probing'), findsOneWidget);
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

    // Last-known data and its stale note remain while polling retries in the
    // background; Home does not expose a competing manual refresh task.
    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.text('Data may be out of date'), findsOneWidget);
    expect(find.byKey(const Key('home-stale-refresh')), findsNothing);
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
    expect(find.byKey(const Key('dashboard-check-button')), findsNothing);
    expect(find.text('Online devices'), findsNothing);
  });

  testWidgets('Home shows device path and latency in a compact preview', (
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
    expect(find.text('offline-printer'), findsNothing);
    // Metric labels add one more occurrence each.
    expect(find.text('Direct'), findsNWidgets(2));
    expect(find.text('Relay'), findsNWidgets(2));
    expect(find.text('probing'), findsOneWidget);
    expect(find.text('Offline'), findsNothing);
    // Useful connection facts stay on the cover; deeper metadata belongs in
    // the opened detail surface.
    expect(find.text('12 ms'), findsOneWidget);
    expect(find.text('43 ms'), findsOneWidget);
    expect(find.text('probe RTT 8 ms'), findsNothing);
    expect(find.text('8 ms'), findsNothing);
  });

  testWidgets(
    'Home keeps online order and moves a reconnected peer to the end',
    (tester) async {
      final base = (await tester.runAsync(_loadFixtureSnapshot))!;
      final initial = _snapshotWithPeers(base, _fourPeerFixtures());
      final api = _FakeDiagnosticsApi(health: true, snapshot: initial);
      final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
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

      double rowTop(String nodeId) =>
          tester.getTopLeft(find.byKey(Key('home-device-row-$nodeId'))).dy;

      expect(rowTop('node-direct'), lessThan(rowTop('node-relay')));
      expect(rowTop('node-relay'), lessThan(rowTop('node-probing')));

      final offlinePeers = _fourPeerFixtures();
      final directOffline = offlinePeers.firstWhere(
        (peer) => peer['node_id'] == 'node-direct',
      );
      directOffline
        ..['online'] = false
        ..['state'] = 'unknown'
        ..['active_path'] = null
        ..['current_path_selection'] = null;
      api.snapshot = _snapshotWithPeers(base, offlinePeers);
      await stores.statusStore.refresh();
      await tester.pump();

      final restoredPeers = _fourPeerFixtures();
      api.snapshot = _snapshotWithPeers(base, restoredPeers);
      await stores.statusStore.refresh();
      await tester.pump();

      expect(rowTop('node-relay'), lessThan(rowTop('node-probing')));
      expect(rowTop('node-probing'), lessThan(rowTop('node-direct')));
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('Device rows order speed, latency, then connection path', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final initialPeers = _fourPeerFixtures();
    final initialSnapshot = _snapshotWithPeers(base, initialPeers);
    final updatedPeers = _fourPeerFixtures();
    final direct = updatedPeers.firstWhere(
      (peer) => peer['node_id'] == 'node-direct',
    );
    direct['bytes_sent'] = 1024 * 1024;
    final updatedSnapshot = _snapshotWithPeers(base, updatedPeers);
    final api = _FakeDiagnosticsApi(health: true, snapshot: initialSnapshot);
    final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    api.snapshot = updatedSnapshot;
    await tester.runAsync(
      () => Future<void>.delayed(const Duration(milliseconds: 20)),
    );
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DashboardPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    final row = find.byKey(const Key('home-device-row-node-direct'));
    final labels = tester
        .widgetList<Text>(find.descendant(of: row, matching: find.byType(Text)))
        .map((text) => text.data)
        .whereType<String>()
        .toList();
    final speedIndex = labels.indexWhere(
      (label) =>
          label.contains('K/S') ||
          label.contains('M/S') ||
          label.contains('G/S'),
    );
    final latencyIndex = labels.indexOf('12 ms');
    final pathIndex = labels.indexOf('Direct');
    expect(speedIndex, greaterThanOrEqualTo(0));
    expect(latencyIndex, greaterThan(speedIndex));
    expect(pathIndex, greaterThan(latencyIndex));
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

    // Attention first, then relay and direct. Offline peers are excluded from
    // the Home preview before the five-device cap is applied.
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

    await tester.tap(find.byKey(const Key('home-device-row-peer-direct-001')));
    await tester.pumpAndSettle();
    // Home hands the selected peer to the real Devices page. The list owns
    // the detail surface, so actions such as speed test are identical from
    // either entry point.
    expect(find.byType(NodesPage), findsOneWidget);
    expect(find.byType(Dialog), findsOneWidget);
    expect(
      find.byKey(const Key('node-detail-speedtest-peer-direct-001')),
      findsOneWidget,
    );
    expect(find.text('24 ms'), findsWidgets);
    await tester.tap(find.byKey(const Key('nodes-detail-close')));
    await tester.pumpAndSettle();

    // A detail opened from Home returns to Home after it is dismissed.
    expect(find.byType(DashboardPage), findsOneWidget);
    expect(find.byType(NodesPage), findsNothing);
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
    final stopButton = find.byKey(const Key('dashboard-stop-button'));
    expect(stopButton, findsOneWidget);
    expect(
      find.descendant(of: stopButton, matching: find.text('Stop P2WLAN')),
      findsOneWidget,
    );
    // The destructive action follows the Virtual IP value, not the network
    // status header, and remains a discoverable full-label button on phones.
    expect(
      tester.getCenter(stopButton).dy,
      greaterThan(tester.getBottomRight(find.text('Virtual IP address')).dy),
    );
    // Healthy: status polling is automatic; the hero does not add a refresh.
    expect(find.byKey(const Key('dashboard-refresh-button')), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Home uses remote-management state on mobile capabilities', (
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
          onOpenDevices: () {},
        ),
      ),
    );

    expect(find.text('Mobile management mode'), findsOneWidget);
    expect(
      find.textContaining('does not start the desktop daemon'),
      findsOneWidget,
    );
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-stop-button')), findsNothing);
    expect(find.byKey(const Key('mobile-home-open-devices')), findsOneWidget);
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

    expect(find.text('Mobile management mode'), findsOneWidget);
    expect(find.text('Cannot reach P2WLAN'), findsNothing);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.text('Start P2WLAN'), findsNothing);
    expect(find.byKey(const Key('dashboard-check-button')), findsNothing);
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
  int? remoteRelayLatencyMs,
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
    'remote_relay_latency_ms': remoteRelayLatencyMs,
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
    remoteRelayLatencyMs: 91,
    direct: _emptyPathHealth(),
    relay: {
      'last_success_age_ms': 300,
      'last_failure_age_ms': null,
      'consecutive_failures': 0,
      'last_error': null,
      'last_error_code': null,
      // Only this daemon's timed peer RTT is displayable. The remote daemon's
      // peer-to-relay RTT above intentionally differs and must be ignored.
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

class _ControllableOfflineDiagnosticsApi extends _FakeDiagnosticsApi {
  _ControllableOfflineDiagnosticsApi() : super(health: false);

  Completer<bool>? _nextHealth;

  Completer<bool> pauseNextHealth() {
    assert(_nextHealth == null, 'A health probe is already paused.');
    return _nextHealth = Completer<bool>();
  }

  @override
  Future<bool> fetchHealth(String diagnosticsUrl) {
    final pending = _nextHealth;
    if (pending == null) return Future<bool>.value(false);
    _nextHealth = null;
    return pending.future;
  }
}
