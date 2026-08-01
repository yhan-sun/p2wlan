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
    expect(find.text('Device summary'), findsOneWidget);
    expect(find.text('Other devices'), findsOneWidget);
    expect(find.text('direct-laptop'), findsOneWidget);
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

    expect(find.text('Other devices'), findsOneWidget);
    expect(find.text('direct-laptop'), findsOneWidget);
    expect(find.text('10.20.0.11'), findsOneWidget);
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
    expect(
      find.text('no direct probe ACK after 320 background UDP retry probes'),
      findsOneWidget,
    );
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
}
