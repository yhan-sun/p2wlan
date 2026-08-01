part of '../p15_widget_test.dart';

void _registerDashboardTests() {
  testWidgets('Dashboard renders offline/error state without crashing', (
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

    expect(find.textContaining('Start P2WLAN to see virtual IP'), findsWidgets);
    expect(find.text('Needs attention'), findsNothing);
    expect(find.byKey(const Key('dashboard-start-button')), findsOneWidget);
    expect(find.byKey(const Key('dashboard-stop-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-refresh-button')), findsOneWidget);
    expect(find.byKey(const Key('auto-refresh-toggle')), findsOneWidget);
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

    expect(find.textContaining('GET /status failed'), findsWidgets);
    expect(find.byKey(const Key('dashboard-start-button')), findsNothing);
    expect(find.byKey(const Key('dashboard-stop-button')), findsOneWidget);
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
    expect(find.byKey(const Key('auto-refresh-toggle')), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
