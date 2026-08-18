part of '../p15_widget_test.dart';

void _registerNodesTests() {
  testWidgets('Nodes renders local device and readable peer sections', (
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

    expect(find.text('This device'), findsOneWidget);
    expect(find.text('studio-mac'), findsOneWidget);
    expect(find.byKey(const Key('nodes-search-field')), findsOneWidget);
    expect(find.byKey(const Key('nodes-filter-all')), findsOneWidget);
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('relay-nas'), findsOneWidget);
    expect(find.byKey(const Key('node-row-peer-direct-001')), findsOneWidget);
    expect(find.byKey(const Key('node-row-peer-relay-002')), findsOneWidget);
    expect(find.text('Peer 数'), findsNothing);
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

  testWidgets('Nodes keeps errored offline peers in the offline group', (
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

    final offlineGroupHeader = find.text('Offline devices').last;
    final erroredOffline = find.text('offline-with-error');
    final plainOffline = find.text('offline-plain');
    expect(offlineGroupHeader, findsOneWidget);
    expect(erroredOffline, findsOneWidget);
    expect(plainOffline, findsOneWidget);
    expect(
      tester.getTopLeft(erroredOffline).dy,
      greaterThan(tester.getTopLeft(offlineGroupHeader).dy),
    );
    expect(
      tester.getTopLeft(plainOffline).dy,
      greaterThan(tester.getTopLeft(offlineGroupHeader).dy),
    );
    // Raw lastError is not dumped into the list; a warning indicator is shown
    // instead. The full error lives in the detail pane.
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

  testWidgets('Nodes details action opens a visible bounded dialog', (
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
    await tester.tap(find.text('View details').last);
    await tester.pumpAndSettle();

    expect(find.byType(Dialog), findsOneWidget);
    expect(find.text('Connection type'), findsOneWidget);
    expect(find.text('Node ID'), findsWidgets);
    expect(find.byType(SelectableText), findsWidgets);
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

    final speedTestButton = find.byKey(
      const Key('node-speedtest-button-peer-direct-001'),
    );
    await tester.ensureVisible(speedTestButton);
    await tester.tap(speedTestButton);
    await tester.pumpAndSettle();

    expect(find.byKey(const Key('node-speedtest-dialog')), findsOneWidget);
    expect(find.text('Test duration: 10 seconds'), findsOneWidget);
    expect(find.text('direct-laptop'), findsWidgets);

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

    final speedTestButton = find.byKey(
      const Key('node-speedtest-button-peer-direct-001'),
    );
    await tester.ensureVisible(speedTestButton);
    await tester.tap(speedTestButton);
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

  testWidgets('Nodes filter chips narrow the device set', (tester) async {
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

    Future<void> tapFilter(String name) async {
      final finder = find.byKey(Key('nodes-filter-$name'));
      await tester.ensureVisible(finder);
      await tester.pump();
      await tester.tap(finder);
      await tester.pump();
    }

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

  testWidgets('Nodes sort by name and by verified latency', (tester) async {
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

    // Name sort: direct-laptop, offline-printer, probing-phone, relay-nas.
    await tester.tap(find.byKey(const Key('nodes-sort-button')));
    await tester.pumpAndSettle();
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

    // Detail pane exists and shows the recommended-first peer.
    expect(find.byKey(const Key('nodes-detail-pane')), findsOneWidget);
    expect(find.text('direct-laptop'), findsWidgets);

    // Clicking the second row updates the detail pane.
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
    // Simulate the peer disappearing from the snapshot.
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

    // No peers at all.
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
    expect(find.text('No other devices yet'), findsOneWidget);
    expect(find.text('No matching devices'), findsNothing);

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
    expect(find.text('No matching devices'), findsOneWidget);
    await tester.tap(find.text('Clear search'));
    await tester.pump();
    expect(find.byKey(const Key('node-row-node-laptop')), findsOneWidget);

    // Filter with no matches.
    final attentionChip = find.byKey(const Key('nodes-filter-attention'));
    await tester.ensureVisible(attentionChip);
    await tester.pump();
    await tester.tap(attentionChip);
    await tester.pump();
    expect(find.text('No matching devices'), findsOneWidget);
    await tester.tap(find.text('Clear filters'));
    await tester.pump();
    expect(find.byKey(const Key('node-row-node-laptop')), findsOneWidget);
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
