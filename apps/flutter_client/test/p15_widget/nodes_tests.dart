part of '../p15_widget_test.dart';

void _registerNodesTests() {
  testWidgets('Nodes renders local device and a continuous device list', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(
          authToken: 'token',
          deviceName: 'studio-mac',
          manualMode: false,
        ),
      ),
    );
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // Compact local-device section: name, IP, status — no Node ID, no sync
    // text, no big panel.
    expect(find.text('This device'), findsOneWidget);
    expect(find.text('studio-mac'), findsOneWidget);
    expect(find.byKey(const Key('nodes-local-row')), findsOneWidget);

    // Toolbar: search + summary + filter/sort menus, never six chips.
    expect(find.byKey(const Key('nodes-search-field')), findsOneWidget);
    expect(find.byKey(const Key('nodes-filter-button')), findsOneWidget);
    expect(find.byKey(const Key('nodes-sort-button')), findsOneWidget);
    expect(find.byType(ChoiceChip), findsNothing);
    expect(find.text('2 devices · 2 online'), findsOneWidget);

    // Continuous list: no group headers, judgment columns only.
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.byKey(const Key('node-row-peer-direct-001')), findsOneWidget);
    expect(find.byKey(const Key('node-row-peer-relay-002')), findsOneWidget);
    expect(find.text('Direct devices'), findsNothing);
    expect(find.text('Offline devices'), findsNothing);

    // First level never shows Node ID or the app version.
    expect(find.text('Node ID'), findsNothing);
    expect(find.text('1.0.0'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes keeps peer list readable on narrow screens', (
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

    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(deviceName: 'studio-mac'),
      ),
    );
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('10.20.0.11'), findsOneWidget);
    expect(find.byKey(const Key('nodes-search-field')), findsOneWidget);
    // No inspector on mobile, no overflow menu on mobile rows.
    expect(find.byKey(const Key('nodes-detail-pane')), findsNothing);
    expect(find.byTooltip('Device actions'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes shows peer RTT for online relay peers', (tester) async {
    final snapshot = (await tester.runAsync(() async {
      final raw =
          jsonDecode(
                await File(
                  'test/fixtures/status_connected.json',
                ).readAsString(),
              )
              as Map<String, dynamic>;
      final relaySelection = raw['relay_selection'] as Map<String, dynamic>;
      relaySelection['selected_rtt_ewma_ms'] = 25;
      relaySelection['selected_last_pong_rtt_ms'] = 19;
      final peers = raw['peers'] as List<dynamic>;
      final relayPeer = peers.cast<Map<String, dynamic>>().firstWhere(
        (peer) => peer['node_id'] == 'peer-relay-002',
      );
      relayPeer['online'] = true;
      relayPeer['state'] = 'relay';
      relayPeer['active_path'] = 'relay';
      (relayPeer['direct'] as Map<String, dynamic>)['latency_ms'] = null;
      (relayPeer['direct'] as Map<String, dynamic>)['rtt_ewma_ms'] = null;
      (relayPeer['relay'] as Map<String, dynamic>)['latency_ms'] = 58;
      (relayPeer['relay'] as Map<String, dynamic>)['rtt_ewma_ms'] = 52;
      return DiagnosticsSnapshot.fromJson(raw);
    }))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.text('52 ms'), findsOneWidget);
    expect(find.text('25 ms'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes offline peers show offline and never a stale path', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final snapshot = (await tester.runAsync(() async {
      final raw =
          jsonDecode(
                await File(
                  'test/fixtures/status_connected.json',
                ).readAsString(),
              )
              as Map<String, dynamic>;
      final peers = raw['peers'] as List<dynamic>;
      for (final peer in peers.cast<Map<String, dynamic>>()) {
        final direct = peer['direct'] as Map<String, dynamic>;
        direct['last_error'] = null;
      }
      peers.addAll([
        {
          'node_id': 'offline-errored-001',
          'device_name': 'offline-with-error',
          'virtual_ip': '10.20.0.20',
          'online': false,
          'last_seen': 1784710187,
          'state': 'closed',
          'active_path': null,
          'direct_type': 'unknown',
          'is_relay': false,
          'direct': {
            'last_error':
                'no direct probe ACK after 320 background UDP retry probes',
          },
          'relay': <String, dynamic>{},
        },
        {
          'node_id': 'offline-plain-002',
          'device_name': 'offline-plain',
          'virtual_ip': '10.20.0.21',
          'online': false,
          'last_seen': 1784710100,
          'state': 'closed',
          'active_path': null,
          'direct_type': 'unknown',
          'is_relay': false,
          'direct': <String, dynamic>{},
          'relay': <String, dynamic>{},
        },
      ]);
      return DiagnosticsSnapshot.fromJson(raw);
    }))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // No group headers: the offline peers live in the same continuous list.
    expect(find.text('Offline devices'), findsNothing);
    expect(find.text('offline-with-error'), findsOneWidget);
    expect(find.text('offline-plain'), findsOneWidget);

    // Offline wins: path column says Offline and latency is —, never a stale
    // Direct/Relay claim or a fabricated latency.
    expect(find.text('Offline'), findsNWidgets(2));
    expect(find.text('—'), findsNWidgets(2));
    expect(find.text('Direct'), findsOneWidget);
    expect(find.text('Relay'), findsOneWidget);
    expect(find.text('10 ms'), findsNothing);

    // Raw lastError is not dumped into the list; a warning indicator is
    // shown instead. The full error lives in the detail surfaces.
    expect(
      find.text('no direct probe ACK after 320 background UDP retry probes'),
      findsNothing,
    );
    expect(find.byIcon(Icons.warning_amber_rounded), findsWidgets);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes remove action opens a visible confirmation dialog', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 1200);
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
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    await tester.tap(find.byTooltip('Device actions').first);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Remove device').last);
    await tester.pumpAndSettle();

    expect(find.byType(AlertDialog), findsOneWidget);
    expect(
      find.textContaining('This removes the device from the control plane'),
      findsOneWidget,
    );
    expect(find.text('direct-laptop'), findsWidgets);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes details hide technical fields behind Advanced', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 1200);
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
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    await tester.tap(find.byKey(const Key('node-row-peer-direct-001')));
    await tester.pumpAndSettle();

    expect(find.byType(Dialog), findsOneWidget);
    // Common info first: connection type and the summary line.
    expect(find.text('Connection type'), findsOneWidget);
    expect(find.text('Direct · 24 ms'), findsOneWidget);
    // Advanced is collapsed: no Node ID, version, or state on the first
    // level of the detail.
    expect(find.text('Node ID'), findsNothing);
    expect(find.text('1.0.0'), findsNothing);
    expect(find.text('State'), findsNothing);

    await tester.tap(find.byKey(const Key('nodes-advanced-toggle')));
    await tester.pumpAndSettle();
    expect(find.text('Node ID'), findsOneWidget);
    expect(find.text('Version'), findsOneWidget);
    expect(find.text('peer-direct-001'), findsOneWidget);
    expect(find.text('direct'), findsOneWidget);
    expect(find.text('—'), findsWidgets); // absent app_version/endpoint → dash
    expect(find.text('State'), findsOneWidget);
    expect(find.text('Copy ping command'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes runs a ten-second speed test for the selected device', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: snapshot,
      speedTestResult: SpeedTestResult(
        peerVirtualIp: '10.20.0.11',
        durationMs: 10000,
        downloadMbps: 123.4,
        uploadMbps: 56.7,
        downloadBytes: 154250000,
        uploadBytes: 70875000,
      ),
    );
    final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // The relay peer carries the "direct probe timed out" note, so it ranks
    // first (needs attention) and its menu is the first on screen.
    await tester.tap(find.byTooltip('Device actions').first);
    await tester.pumpAndSettle();
    await tester.tap(
      find.byKey(const Key('node-speedtest-action-peer-relay-002')),
    );
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('node-speedtest-dialog')), findsOneWidget);
    expect(find.text('Test duration: 10 seconds'), findsOneWidget);
    expect(find.text('relay-nas'), findsWidgets);

    await tester.tap(find.byKey(const Key('node-speedtest-start')));
    await tester.pump();
    await tester.runAsync(() async {});
    await tester.pumpAndSettle();

    expect(api.speedTestCount, 1);
    expect(find.text('123.4 Mbps'), findsOneWidget);
    expect(find.text('56.7 Mbps'), findsOneWidget);
    expect(find.text('147.1 MB / 67.6 MB'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes shows a speed-test failure and allows retry', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: snapshot,
      speedTestError: const DiagnosticsApiException('speed fixture failed'),
    );
    final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    await tester.tap(find.byTooltip('Device actions').first);
    await tester.pumpAndSettle();
    await tester.tap(
      find.byKey(const Key('node-speedtest-action-peer-relay-002')),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('node-speedtest-start')));
    await tester.pump();
    await tester.runAsync(() async {});
    await tester.pumpAndSettle();

    expect(
      find.textContaining('Speed test failed: speed fixture failed'),
      findsOneWidget,
    );
    expect(find.text('Run again'), findsOneWidget);

    await tester.tap(find.byKey(const Key('node-speedtest-start')));
    await tester.pump();
    await tester.runAsync(() async {});
    await tester.pumpAndSettle();
    expect(api.speedTestCount, 2);
  });

  testWidgets('Nodes searches by name, IP, and node ID', (tester) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final snapshot = _snapshotWithPeers(base, _searchPeerFixtures());
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);

    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    final search = find.byKey(const Key('nodes-search-field'));
    await tester.enterText(search, 'nas');
    await tester.pump();
    expect(find.byKey(const Key('node-row-node-nas')), findsOneWidget);
    expect(find.byKey(const Key('node-row-node-laptop')), findsNothing);
    expect(find.byKey(const Key('node-row-node-office')), findsNothing);

    await tester.enterText(search, '10.20.0.32');
    await tester.pump();
    expect(find.byKey(const Key('node-row-node-office')), findsOneWidget);
    expect(find.byKey(const Key('node-row-node-nas')), findsNothing);

    await tester.enterText(search, 'node-laptop');
    await tester.pump();
    expect(find.byKey(const Key('node-row-node-laptop')), findsOneWidget);
    expect(find.byKey(const Key('node-row-node-office')), findsNothing);

    await tester.tap(find.byKey(const Key('nodes-search-clear')));
    await tester.pump();
    expect(find.byKey(const Key('node-row-node-laptop')), findsOneWidget);
    expect(find.byKey(const Key('node-row-node-nas')), findsOneWidget);
    expect(find.byKey(const Key('node-row-node-office')), findsOneWidget);
  });

  testWidgets('Nodes filter menu offers all six filters and narrows the set', (
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
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // No chip row at all — the filter is a single menu.
    expect(find.byType(ChoiceChip), findsNothing);

    Future<void> openFilter() async {
      await tester.tap(find.byKey(const Key('nodes-filter-button')));
      await tester.pumpAndSettle();
    }

    Future<void> tapFilter(String name) async {
      await openFilter();
      await tester.tap(find.byKey(Key('nodes-filter-$name')));
      await tester.pumpAndSettle();
    }

    // The menu exposes every filter (menu items are keyed; the page itself
    // also renders some of the same labels in the rows).
    await openFilter();
    for (final name in [
      'all',
      'online',
      'direct',
      'relay',
      'attention',
      'offline',
    ]) {
      expect(find.byKey(Key('nodes-filter-$name')), findsOneWidget);
    }
    await tester.tap(find.byKey(const Key('nodes-filter-all')));
    await tester.pumpAndSettle();

    int rowCount() => tester
        .widgetList(find.byWidgetPredicate((widget) => widget is InkWell))
        .where((widget) => widget.key?.toString().contains('node-row-') == true)
        .length;

    expect(rowCount(), 4); // All
    await tapFilter('online');
    expect(rowCount(), 3);
    await tapFilter('direct');
    expect(rowCount(), 1);
    await tapFilter('relay');
    expect(rowCount(), 1);
    await tapFilter('attention');
    expect(rowCount(), 1);
    await tapFilter('offline');
    expect(rowCount(), 1);
    await tapFilter('all');
    expect(rowCount(), 4);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes sort menu orders by name and by verified latency', (
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
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    double rowTop(String nodeId) =>
        tester.getTopLeft(find.byKey(Key('node-row-$nodeId'))).dy;

    // The sort menu exposes Default / Name / Latency.
    await tester.tap(find.byKey(const Key('nodes-sort-button')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('nodes-sort-recommended')), findsOneWidget);
    expect(find.byKey(const Key('nodes-sort-name')), findsOneWidget);
    expect(find.byKey(const Key('nodes-sort-latency')), findsOneWidget);

    // Name sort: direct-laptop, offline-printer, probing-phone, relay-nas.
    await tester.tap(find.text('Name').last);
    await tester.pumpAndSettle();
    expect(rowTop('node-direct'), lessThan(rowTop('node-offline')));
    expect(rowTop('node-offline'), lessThan(rowTop('node-probing')));
    expect(rowTop('node-probing'), lessThan(rowTop('node-relay')));

    // Latency sort: direct (12 ms) before relay (43 ms); probing and offline
    // have no verified latency and sort after them by name. Probe RTT (8 ms)
    // is not a latency and must not place probing-phone first.
    await tester.tap(find.byKey(const Key('nodes-sort-button')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Latency').last);
    await tester.pumpAndSettle();
    expect(rowTop('node-direct'), lessThan(rowTop('node-relay')));
    expect(rowTop('node-relay'), lessThan(rowTop('node-offline')));
    expect(rowTop('node-offline'), lessThan(rowTop('node-probing')));
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes expanded layout keeps selection across refresh', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

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
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // Master/detail exists and the recommended-first peer is selected by
    // default: the probing peer needs attention and ranks first.
    expect(find.byKey(const Key('nodes-detail-pane')), findsOneWidget);
    expect(find.text('probing-phone'), findsWidgets);

    // Clicking the second row updates the detail pane in place.
    await tester.tap(find.byKey(const Key('node-row-node-relay')));
    await tester.pump();
    expect(find.text('relay-nas'), findsWidgets);
    expect(find.byType(Dialog), findsNothing);

    // StatusStore refresh keeps the selection.
    await stores.statusStore.refresh();
    await tester.pump();
    expect(find.text('relay-nas'), findsWidgets);

    // Removing the selected peer hides it and falls back to the first visible
    // peer instead of showing stale details.
    final api = stores.statusStore;
    final pruned = _snapshotWithPeers(
      base,
      _fourPeerFixtures().where((p) => p['node_id'] != 'node-relay').toList(),
    );
    (api.diagnosticsApi as _FakeDiagnosticsApi).snapshot = pruned;
    await api.refresh();
    await tester.pump();
    expect(find.text('relay-nas'), findsNothing);
    expect(find.byKey(const Key('nodes-detail-pane')), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes expanded rows hide Node ID and version until Advanced', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

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
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    final pane = find.byKey(const Key('nodes-detail-pane'));
    Finder paneText(String text) =>
        find.descendant(of: pane, matching: find.text(text));

    // Rows and collapsed inspector: no Node ID, no version, no state.
    expect(find.text('Node ID'), findsNothing);
    expect(find.text('Version'), findsNothing);
    expect(find.text('1.0.0'), findsNothing);
    expect(paneText('Node ID'), findsNothing);

    // Inspector header answers who/online/how without technical fields.
    expect(paneText('probing-phone'), findsOneWidget);
    expect(paneText('10.20.0.13'), findsWidgets); // header + network section

    // Expanding Advanced reveals the technical metadata.
    await tester.tap(find.byKey(const Key('nodes-advanced-toggle')));
    await tester.pumpAndSettle();
    expect(paneText('Node ID'), findsOneWidget);
    expect(paneText('Version'), findsOneWidget);
    expect(paneText('1.0.0'), findsOneWidget);
    expect(paneText('State'), findsOneWidget);
    // List rows themselves never show version even after expansion.
    expect(find.text('1.0.0'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes responsive detail flows across breakpoints', (
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

    // Compact: mobile full-screen detail, no master-detail.
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );
    await tester.pump();
    expect(find.byKey(const Key('nodes-detail-pane')), findsNothing);
    expect(tester.takeException(), isNull);

    await tester.tap(find.byKey(const Key('node-row-node-direct')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('nodes-mobile-detail')), findsOneWidget);
    expect(find.text('10.20.0.11'), findsWidgets);
    expect(tester.takeException(), isNull);
    await tester.tap(find.byType(CloseButton));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('nodes-mobile-detail')), findsNothing);
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();

    // Medium: no master-detail, row opens the dialog.
    tester.view.physicalSize = const Size(700, 1000);
    tester.view.devicePixelRatio = 1;
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );
    await tester.pump();
    expect(find.byKey(const Key('nodes-detail-pane')), findsNothing);
    await tester.tap(find.byKey(const Key('node-row-node-direct')));
    await tester.pumpAndSettle();
    expect(find.byType(Dialog), findsOneWidget);
    expect(find.text('Connection type'), findsOneWidget);
    await tester.tap(find.byTooltip('Cancel'));
    await tester.pumpAndSettle();
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();

    // Expanded: master-detail, no dialog on row tap.
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1;
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );
    await tester.pump();
    expect(find.byKey(const Key('nodes-detail-pane')), findsOneWidget);
    await tester.tap(find.byKey(const Key('node-row-node-relay')));
    await tester.pump();
    expect(find.byType(Dialog), findsNothing);
    expect(find.byKey(const Key('nodes-detail-pane')), findsOneWidget);
    expect(tester.takeException(), isNull);
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });

  testWidgets('Nodes distinguishes empty states', (tester) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: base)),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();

    // No peers at all: the local device still renders above the empty state.
    final noPeersSnapshot = _snapshotWithPeers(base, []);
    (stores.statusStore.diagnosticsApi as _FakeDiagnosticsApi).snapshot =
        noPeersSnapshot;
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );
    await tester.pump();
    expect(find.text('This device'), findsOneWidget);
    expect(find.text('No other devices yet'), findsOneWidget);
    expect(find.text('No devices found'), findsNothing);

    // Search with no matches.
    final searchSnapshot = _snapshotWithPeers(base, _searchPeerFixtures());
    (stores.statusStore.diagnosticsApi as _FakeDiagnosticsApi).snapshot =
        searchSnapshot;
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );
    await tester.enterText(find.byKey(const Key('nodes-search-field')), 'zzz');
    await tester.pump();
    expect(find.text('No devices found'), findsOneWidget);
    await tester.tap(find.text('Clear search'));
    await tester.pump();
    expect(find.byKey(const Key('node-row-node-laptop')), findsOneWidget);

    // Filter with no matches, via the filter menu.
    await tester.tap(find.byKey(const Key('nodes-filter-button')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('nodes-filter-attention')));
    await tester.pumpAndSettle();
    expect(find.text('No devices match this filter'), findsOneWidget);
    await tester.tap(find.text('Clear filters'));
    await tester.pump();
    expect(find.byKey(const Key('node-row-node-laptop')), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes detail selection always follows search/filter results', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);

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
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    final pane = find.byKey(const Key('nodes-detail-pane'));
    Finder paneText(String text) =>
        find.descendant(of: pane, matching: find.text(text));

    // Select the Relay peer; the detail pane shows it.
    await tester.tap(find.byKey(const Key('node-row-node-relay')));
    await tester.pump();
    expect(paneText('relay-nas'), findsOneWidget);

    // Filter to Direct via the menu: the Relay row disappears and the detail
    // must switch to a Direct peer instead of showing the hidden Relay.
    await tester.tap(find.byKey(const Key('nodes-filter-button')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('nodes-filter-direct')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('node-row-node-relay')), findsNothing);
    expect(paneText('direct-laptop'), findsOneWidget);
    expect(paneText('relay-nas'), findsNothing);

    // Clearing the filter restores the list without exceptions; the stale
    // selection must not resurrect a hidden peer.
    await tester.tap(find.byKey(const Key('nodes-filter-button')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('nodes-filter-all')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('node-row-node-relay')), findsOneWidget);
    expect(tester.takeException(), isNull);

    // Search for the Direct device's name while Relay is selected: the detail
    // must follow the search results, not the persistent selection.
    await tester.tap(find.byKey(const Key('node-row-node-relay')));
    await tester.pump();
    expect(paneText('relay-nas'), findsOneWidget);
    await tester.enterText(
      find.byKey(const Key('nodes-search-field')),
      'direct-laptop',
    );
    await tester.pump();
    expect(find.byKey(const Key('node-row-node-relay')), findsNothing);
    expect(paneText('direct-laptop'), findsOneWidget);
    expect(paneText('relay-nas'), findsNothing);
  });

  testWidgets('Nodes closes detail surfaces only on successful removal', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final snapshot = _snapshotWithPeers(base, _fourPeerFixtures());

    // Medium: successful removal closes the dialog.
    final okApi = _FakeControlApi();
    final okStores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(okStores.dispose);
    await okStores.statusStore.refresh();
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          key: const ValueKey('nodes-ok'),
          settingsStore: okStores.settingsStore,
          statusStore: okStores.statusStore,
          controlApi: okApi,
        ),
      ),
    );
    await tester.tap(find.byKey(const Key('node-row-node-direct')));
    await tester.pumpAndSettle();
    expect(find.byType(Dialog), findsOneWidget);
    final okRemoveAction = find.text('Remove device').first;
    await tester.ensureVisible(okRemoveAction);
    await tester.pumpAndSettle();
    await tester.tap(okRemoveAction);
    await tester.pumpAndSettle();
    await tester.tap(
      find.descendant(
        of: find.byType(FilledButton),
        matching: find.text('Remove device'),
      ),
    );
    await tester.pumpAndSettle();
    expect(okApi.deleteCalls, 1);
    expect(find.byType(Dialog), findsNothing);
    expect(find.text('direct-laptop'), findsNothing);
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();

    // Medium: cancel keeps the dialog open.
    final cancelApi = _FakeControlApi();
    final cancelStores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(cancelStores.dispose);
    await cancelStores.statusStore.refresh();
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          key: const ValueKey('nodes-cancel'),
          settingsStore: cancelStores.settingsStore,
          statusStore: cancelStores.statusStore,
          controlApi: cancelApi,
        ),
      ),
    );
    await tester.tap(find.byKey(const Key('node-row-node-direct')));
    await tester.pumpAndSettle();
    final cancelRemoveAction = find.text('Remove device').first;
    await tester.ensureVisible(cancelRemoveAction);
    await tester.pumpAndSettle();
    await tester.tap(cancelRemoveAction);
    await tester.pumpAndSettle();
    await tester.tap(find.text('Cancel'));
    await tester.pumpAndSettle();
    expect(cancelApi.deleteCalls, 0);
    expect(find.byType(Dialog), findsOneWidget);
    await tester.tap(find.byTooltip('Cancel'));
    await tester.pumpAndSettle();
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();

    // Medium: failed deletion keeps the dialog open.
    final failApi = _FakeControlApi(failDelete: true);
    final failStores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(failStores.dispose);
    await failStores.statusStore.refresh();
    tester.view.physicalSize = const Size(800, 1200);
    tester.view.devicePixelRatio = 1;
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          key: const ValueKey('nodes-fail'),
          settingsStore: failStores.settingsStore,
          statusStore: failStores.statusStore,
          controlApi: failApi,
        ),
      ),
    );
    await tester.tap(find.byKey(const Key('node-row-node-direct')));
    await tester.pumpAndSettle();
    final failRemoveAction = find.text('Remove device').first;
    await tester.ensureVisible(failRemoveAction);
    await tester.pumpAndSettle();
    await tester.tap(failRemoveAction);
    await tester.pumpAndSettle();
    await tester.tap(
      find.descendant(
        of: find.byType(FilledButton),
        matching: find.text('Remove device'),
      ),
    );
    await tester.pumpAndSettle();
    expect(failApi.deleteCalls, 1);
    expect(find.byType(Dialog), findsOneWidget);
    await tester.tap(find.byTooltip('Cancel'));
    await tester.pumpAndSettle();
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();

    // Compact: successful removal pops the mobile detail route.
    final mobileApi = _FakeControlApi();
    final mobileStores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(mobileStores.dispose);
    await mobileStores.statusStore.refresh();
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          key: const ValueKey('nodes-mobile'),
          settingsStore: mobileStores.settingsStore,
          statusStore: mobileStores.statusStore,
          controlApi: mobileApi,
        ),
      ),
    );
    await tester.tap(find.byKey(const Key('node-row-node-direct')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('nodes-mobile-detail')), findsOneWidget);
    final mobileRemoveAction = find.text('Remove device').first;
    await tester.ensureVisible(mobileRemoveAction);
    await tester.pumpAndSettle();
    await tester.tap(mobileRemoveAction);
    await tester.pumpAndSettle();
    await tester.tap(
      find.descendant(
        of: find.byType(FilledButton),
        matching: find.text('Remove device'),
      ),
    );
    await tester.pumpAndSettle();
    expect(mobileApi.deleteCalls, 1);
    expect(find.byKey(const Key('nodes-mobile-detail')), findsNothing);
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
  });

  testWidgets('Nodes online count matches the online filter', (tester) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final ghostPeer = _peerJson(
      nodeId: 'node-ghost',
      deviceName: 'ghost-device',
      virtualIp: '10.20.0.40',
      online: true,
      state: 'unknown',
      activePath: null,
      relayConfirmedEndpoint: null,
      direct: _emptyPathHealth(),
      relay: _emptyPathHealth(),
    );
    final snapshot = _snapshotWithPeers(base, [
      _searchPeerFixtures()[0],
      ghostPeer,
    ]);
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // The peer reports online=true but has no verified usable path (its
    // computed path is offline). Summary and the Online filter must agree.
    expect(find.text('2 devices · 1 online'), findsOneWidget);

    await tester.tap(find.byKey(const Key('nodes-filter-button')));
    await tester.pumpAndSettle();
    await tester.tap(find.byKey(const Key('nodes-filter-online')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('node-row-node-laptop')), findsOneWidget);
    expect(find.byKey(const Key('node-row-node-ghost')), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes shows a stale hint while keeping last-known data', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
        enableFreshnessTimer: true,
        maxSnapshotAge: const Duration(milliseconds: 300),
      ),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();
    await tester.pump(const Duration(milliseconds: 600));

    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // Last-known list stays; the header hint flags staleness.
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.text('Stale'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Nodes details use explicit locale path labels across surfaces', (
    tester,
  ) async {
    final base = (await tester.runAsync(_loadFixtureSnapshot))!;
    final snapshot = _snapshotWithPeers(base, _fourPeerFixtures());

    // English scope: labels stay English inside the dialog route even
    // though that route is outside the home AppStringsScope (whose fallback
    // is the default language, zh-Hans).
    final enStores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(enStores.dispose);
    await enStores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: NodesPage(
          key: const ValueKey('nodes-badge-en'),
          settingsStore: enStores.settingsStore,
          statusStore: enStores.statusStore,
        ),
      ),
    );
    await tester.tap(find.byKey(const Key('node-row-node-direct')));
    await tester.pumpAndSettle();
    expect(find.byType(Dialog), findsOneWidget);
    expect(
      find.descendant(of: find.byType(Dialog), matching: find.text('Direct')),
      findsWidgets,
    );
    expect(
      find.descendant(of: find.byType(Dialog), matching: find.text('直连')),
      findsNothing,
    );
    await tester.tap(find.byTooltip('Cancel'));
    await tester.pumpAndSettle();

    // Chinese scope: explicit zh strings must reach the dialog.
    final zhStores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      ),
    ))!;
    addTearDown(zhStores.dispose);
    await zhStores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        strings: AppStrings.fromCode('zh'),
        child: NodesPage(
          key: const ValueKey('nodes-badge-zh'),
          settingsStore: zhStores.settingsStore,
          statusStore: zhStores.statusStore,
        ),
      ),
    );
    await tester.tap(find.byKey(const Key('node-row-node-direct')));
    await tester.pumpAndSettle();
    expect(find.byType(Dialog), findsOneWidget);
    expect(
      find.descendant(of: find.byType(Dialog), matching: find.text('直连')),
      findsWidgets,
    );
    expect(
      find.descendant(of: find.byType(Dialog), matching: find.text('Direct')),
      findsNothing,
    );
    await tester.tap(find.byTooltip('取消'));
    await tester.pumpAndSettle();

    // Verified relay peer keeps its localized path label in the dialog too.
    final relayRow = find.byKey(const Key('node-row-node-relay'));
    await tester.ensureVisible(relayRow);
    await tester.pumpAndSettle();
    await tester.tap(relayRow);
    await tester.pumpAndSettle();
    expect(
      find.descendant(of: find.byType(Dialog), matching: find.text('中继')),
      findsWidgets,
    );
    await tester.tap(find.byTooltip('取消'));
    await tester.pumpAndSettle();

    // Compact mobile detail route preserves the explicit locale strings.
    tester.view.physicalSize = const Size(390, 844);
    tester.view.devicePixelRatio = 1;
    await tester.pumpWidget(
      _TestApp(
        strings: AppStrings.fromCode('zh'),
        child: NodesPage(
          key: const ValueKey('nodes-badge-zh-mobile'),
          settingsStore: zhStores.settingsStore,
          statusStore: zhStores.statusStore,
        ),
      ),
    );
    await tester.tap(find.byKey(const Key('node-row-node-direct')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('nodes-mobile-detail')), findsOneWidget);
    expect(
      find.descendant(
        of: find.byKey(const Key('nodes-mobile-detail')),
        matching: find.text('直连'),
      ),
      findsWidgets,
    );
    expect(
      find.descendant(
        of: find.byKey(const Key('nodes-mobile-detail')),
        matching: find.text('Direct'),
      ),
      findsNothing,
    );
    tester.view.resetPhysicalSize();
    tester.view.resetDevicePixelRatio();
    expect(tester.takeException(), isNull);
  });
}

/// Three peers for search coverage: Laptop / NAS / Office PC with distinct
/// names, IPs, and node IDs.
List<Map<String, dynamic>> _searchPeerFixtures() {
  return [
    _peerJson(
      nodeId: 'node-laptop',
      deviceName: 'Laptop',
      virtualIp: '10.20.0.31',
      online: true,
      state: 'direct',
      activePath: 'direct',
      relayConfirmedEndpoint: null,
      direct: _latencyPathHealth(21),
      relay: _emptyPathHealth(),
      currentPathSelection: _directSelection(),
    ),
    _peerJson(
      nodeId: 'node-nas',
      deviceName: 'NAS',
      virtualIp: '10.20.0.33',
      online: true,
      state: 'relay',
      activePath: 'relay',
      relayConfirmedEndpoint: '203.0.113.10:18081',
      relayConfirmedGeneration: 5,
      direct: _emptyPathHealth(),
      relay: _latencyPathHealth(33),
      currentPathSelection: _relaySelection(),
    ),
    _peerJson(
      nodeId: 'node-office',
      deviceName: 'Office PC',
      virtualIp: '10.20.0.32',
      online: true,
      state: 'direct',
      activePath: 'direct',
      relayConfirmedEndpoint: null,
      direct: _latencyPathHealth(18),
      relay: _emptyPathHealth(),
      currentPathSelection: _directSelection(),
    ),
  ];
}

Map<String, dynamic> _latencyPathHealth(int latencyMs) => {
  'last_success_age_ms': 100,
  'last_failure_age_ms': null,
  'consecutive_failures': 0,
  'last_error': null,
  'last_error_code': null,
  'latency_ms': latencyMs,
  'rtt_ewma_ms': null,
};

Map<String, dynamic> _directSelection() => {
  'path': 'direct',
  'direct_endpoint': '198.51.100.30:60000',
  'reason_code': 'path_direct_confirmed',
  'reason': 'public UDP pair confirmed',
  'direct_confirmed': true,
  'relay_hedged': false,
};

Map<String, dynamic> _relaySelection() => {
  'path': 'relay',
  'direct_endpoint': null,
  'reason_code': 'path_relay_fallback',
  'reason': 'direct path unavailable; relay confirmed',
  'direct_confirmed': false,
  'relay_hedged': false,
};
