part of '../p15_widget_test.dart';

/// Network & route diagnostics migrated from the deleted Tunnels page into
/// Troubleshooting → Advanced. Every former Tunnels behavior keeps coverage
/// here — nothing was dropped by removing the standalone page.
void _registerNetworkTests() {
  const macosCaps = PlatformCapabilities(
    canControlLocalDaemon: true,
    canRequestElevation: true,
    canVerifyRoutes: true,
    canRepairRoutes: true,
    canOpenLocalLogs: true,
    canCreateSupportBundle: true,
    canUseSystemTray: true,
    canActAsLocalVpnNode: true,
    canManageRemoteDevices: true,
  );

  const noRepairCaps = PlatformCapabilities(
    canControlLocalDaemon: true,
    canRequestElevation: true,
    canVerifyRoutes: true,
    canRepairRoutes: false,
    canOpenLocalLogs: true,
    canCreateSupportBundle: true,
    canUseSystemTray: true,
    canActAsLocalVpnNode: true,
    canManageRemoteDevices: true,
  );

  const noRestartCaps = PlatformCapabilities(
    canControlLocalDaemon: false,
    canRequestElevation: true,
    canVerifyRoutes: true,
    canRepairRoutes: true,
    canOpenLocalLogs: true,
    canCreateSupportBundle: true,
    canUseSystemTray: true,
    canActAsLocalVpnNode: true,
    canManageRemoteDevices: true,
  );

  Future<_Stores> pumpNetworkPage(
    WidgetTester tester, {
    required DiagnosticsApi api,
    PlatformCapabilities capabilities = macosCaps,
    DaemonController? daemonController,
    bool expandAdvanced = true,
  }) async {
    final stores = (await tester.runAsync(
      () => _makeStores(api: api, daemonController: daemonController),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();
    await tester.pumpWidget(
      _TestApp(
        child: DiagnosticsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: capabilities,
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );
    if (expandAdvanced) {
      await _expandAdvanced(tester);
    }
    return stores;
  }

  const installedRoutes = _fakeRoutes;
  const missingRoutes = missingRoutesFixture;
  const conflictRoutes = conflictRoutesFixture;
  const noChangeRepair = noChangeRepairFixture;

  testWidgets(
    'verify route installed: authoritative state, no guessed health',
    (tester) async {
      final api = _FakeDiagnosticsApi(
        health: true,
        snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
        routes: installedRoutes,
      );
      await pumpNetworkPage(tester, api: api);

      // The route badge is green only because the daemon said "installed".
      expect(find.text('Installed'), findsOneWidget);
      expect(find.text('Check routes'), findsOneWidget);
      expect(
        find.textContaining('Authoritative state: installed.'),
        findsOneWidget,
      );
      expect(find.text('Missing'), findsNothing);
      expect(find.text('Conflict'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('verify route missing: never inferred as healthy', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
      routes: missingRoutes,
    );
    await pumpNetworkPage(tester, api: api);

    expect(find.text('Missing'), findsOneWidget);
    expect(
      find.textContaining('Authoritative state: missing.'),
      findsOneWidget,
    );
    // Repair becomes a prominent action when the route is missing.
    expect(find.text('Repair routes'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('verify route conflict surfaces actual interface', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
      routes: conflictRoutes,
    );
    await pumpNetworkPage(tester, api: api);

    expect(find.text('Conflict'), findsOneWidget);
    expect(
      find.textContaining('Authoritative state: conflict.'),
      findsOneWidget,
    );
    expect(find.text('en0'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('repair success shows inline confirmation and new state', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
      routes: missingRoutes,
    );
    await pumpNetworkPage(tester, api: api);

    // Repair installs the route; the follow-up authoritative verify reflects it.
    api.routes = installedRoutes;
    await _tapVisible(tester, find.text('Repair routes'));

    expect(
      find.text(
        'Route repaired in place (state: installed) without restarting the daemon.',
      ),
      findsOneWidget,
    );
    expect(find.text('Installed'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('repair already installed reports no change', (tester) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
      routes: installedRoutes,
      repairResult: noChangeRepair,
    );
    await pumpNetworkPage(tester, api: api);

    // Route installed → repair is a low-weight text action, never highlighted.
    expect(find.widgetWithText(TextButton, 'Repair routes'), findsOneWidget);
    expect(find.text('No fix needed'), findsOneWidget);
    await _tapVisible(tester, find.text('Repair routes'));

    expect(
      find.text('Route was already correctly installed; no change needed.'),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('repair failure is localized and redacted', (tester) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
      routes: missingRoutes,
      repairRoutesError: Exception('SUPER_SECRET'),
    );
    await pumpNetworkPage(tester, api: api);

    await _tapVisible(tester, find.text('Repair routes'));

    expect(
      find.text('Could not repair routes. Please try again.'),
      findsOneWidget,
    );
    expect(find.textContaining('SUPER_SECRET'), findsNothing);
    expect(find.textContaining('Exception'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('restart failure is localized and redacted', (tester) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    final failing = _FailingDaemonController(api);
    await pumpNetworkPage(tester, api: api, daemonController: failing);

    await _tapVisible(
      tester,
      find.text('Restart network service (brief disconnect)'),
    );
    await tester.pumpAndSettle();

    expect(
      find.text('Could not restart the network service. Please try again.'),
      findsOneWidget,
    );
    expect(find.textContaining('SocketException'), findsNothing);
    expect(find.textContaining('SECRET'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('restart success reports route reinstall', (tester) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    await pumpNetworkPage(tester, api: api);

    await _tapVisible(
      tester,
      find.text('Restart network service (brief disconnect)'),
    );

    expect(
      find.text('Daemon restarted to reinstall overlay routes.'),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('canVerifyRoutes=false hides verify and never verifies', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    await pumpNetworkPage(
      tester,
      api: api,
      capabilities: PlatformCapabilities.fromPlatform('ios'),
    );

    expect(find.text('Check routes'), findsNothing);
    expect(find.text('Repair routes'), findsNothing);
    expect(
      find.text('Restart network service (brief disconnect)'),
      findsNothing,
    );
    // The store's own refresh() verifies; the page must not add another one
    // for a platform that cannot perform local route operations.
    expect(api.verifyRoutesCount, 1);
    expect(tester.takeException(), isNull);
  });

  testWidgets('canRepairRoutes=false hides repair but keeps verify', (
    tester,
  ) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    await pumpNetworkPage(tester, api: api, capabilities: noRepairCaps);

    expect(find.text('Check routes'), findsOneWidget);
    expect(find.text('Repair routes'), findsNothing);
    expect(
      find.text('Restart network service (brief disconnect)'),
      findsOneWidget,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('canControlLocalDaemon=false hides restart', (tester) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    await pumpNetworkPage(tester, api: api, capabilities: noRestartCaps);

    expect(find.text('Check routes'), findsOneWidget);
    expect(find.text('Repair routes'), findsOneWidget);
    expect(
      find.text('Restart network service (brief disconnect)'),
      findsNothing,
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('network rows stay readable on narrow screens', (tester) async {
    await tester.binding.setSurfaceSize(const Size(390, 844));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    await pumpNetworkPage(tester, api: api);

    expect(find.text('Virtual Adapter'), findsOneWidget);
    expect(find.text('Virtual IP'), findsOneWidget);
    expect(find.text('10.20.0.10'), findsOneWidget);
    expect(find.text('192.0.2.10:60207'), findsOneWidget);
    expect(find.text('Check routes'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('dispose mid-restart does not throw', (tester) async {
    final api = _FakeDiagnosticsApi(
      health: true,
      snapshot: (await tester.runAsync(_loadFixtureSnapshot)),
    );
    final hanging = _HangingDaemonController(api);
    await pumpNetworkPage(tester, api: api, daemonController: hanging);

    await _tapVisibleNoSettle(
      tester,
      find.text('Restart network service (brief disconnect)'),
    );

    await tester.pumpWidget(const SizedBox.shrink());
    hanging.completeAll();
    await tester.pump();

    expect(tester.takeException(), isNull);
  });
}

/// Scrolls [finder] into view and taps it, settling the advanced sections.
Future<void> _tapVisible(WidgetTester tester, Finder finder) async {
  await tester.ensureVisible(finder);
  await tester.pumpAndSettle();
  await tester.tap(finder);
  await tester.pumpAndSettle();
}

/// Same as [_tapVisible] but without settling: used while a daemon operation
/// stays in flight (e.g. the dispose mid-restart test).
Future<void> _tapVisibleNoSettle(WidgetTester tester, Finder finder) async {
  await tester.ensureVisible(finder);
  await tester.pump();
  await tester.tap(finder);
  await tester.pump();
}

const missingRoutesFixture = RoutesResponse(
  contractVersion: 1,
  interfaceName: 'p2wlan0',
  mtu: 1420,
  healthy: false,
  conflictCount: 0,
  entries: [
    RouteEntryResponse(
      cidr: '10.20.0.0/16',
      expectedInterface: 'p2wlan0',
      actualInterface: null,
      state: 'missing',
      owned: true,
    ),
  ],
);

const conflictRoutesFixture = RoutesResponse(
  contractVersion: 1,
  interfaceName: 'p2wlan0',
  mtu: 1420,
  healthy: false,
  conflictCount: 1,
  entries: [
    RouteEntryResponse(
      cidr: '10.20.0.0/16',
      expectedInterface: 'p2wlan0',
      actualInterface: 'en0',
      state: 'conflict',
      owned: false,
    ),
  ],
);

const noChangeRepairFixture = RouteRepairResponse(
  contractVersion: 1,
  cidr: '10.20.0.0/16',
  changed: false,
  attempted: true,
  before: 'installed',
  after: 'installed',
  reason: 'already installed',
  restartedDaemon: false,
);
