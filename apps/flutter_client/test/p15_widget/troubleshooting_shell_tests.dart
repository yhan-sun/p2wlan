part of '../p15_widget_test.dart';

/// Full-shell Phase 5 integration: no Tunnels navigation anywhere, issue
/// actions wired through the real shell, responsive troubleshooting, dark mode.
void _registerTroubleshootingShellTests() {
  Future<void> pumpShell(
    WidgetTester tester,
    Size size, {
    required _Stores stores,
    PlatformCapabilities? capabilities,
  }) async {
    await tester.binding.setSurfaceSize(size);
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      _DesignSystemHost(
        dark: false,
        child: P2WlanShell(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities:
              capabilities ?? PlatformCapabilities.fromPlatform('macos'),
        ),
      ),
    );
    await tester.pumpAndSettle();
  }

  Future<void> goToTroubleshooting(WidgetTester tester) async {
    // Troubleshooting is no longer a permanent left-nav item. Expanded
    // desktop reaches it from the status footer; compact desktop uses the
    // icon-only footer; phones keep the overflow entry.
    final desktopFooter = find.byKey(const Key('desktop-sidebar-status'));
    if (desktopFooter.evaluate().isNotEmpty) {
      await tester.tap(desktopFooter);
      await tester.pumpAndSettle();
      return;
    }
    final compactFooter = find.byKey(const Key('compact-sidebar-status'));
    if (compactFooter.evaluate().isNotEmpty) {
      await tester.tap(compactFooter);
      await tester.pumpAndSettle();
      return;
    }

    final shellAction = find.byKey(const Key('shell-open-troubleshooting'));
    if (shellAction.evaluate().isNotEmpty) {
      await tester.tap(shellAction);
      await tester.pumpAndSettle();
      return;
    }

    // Mobile: troubleshooting lives in the top-bar overflow menu.
    await tester.tap(find.byIcon(Icons.more_horiz_rounded));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Troubleshooting'));
    await tester.pumpAndSettle();
  }

  Future<_Stores> healthyStores(WidgetTester tester) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final clean = _mutateSnapshot(snapshot, _clearPeerErrors);
    final stores = (await tester.runAsync(
      () =>
          _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: clean)),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();
    return stores;
  }

  Future<_Stores> peerWarningStores(WidgetTester tester) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final warn = _mutateSnapshot(snapshot, (raw) {
      _clearPeerErrors(raw);
      (raw['peers'] as List<dynamic>)[0]['direct']['last_error'] = 'stale';
      return raw;
    });
    final stores = (await tester.runAsync(
      () => _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: warn)),
    ))!;
    addTearDown(stores.dispose);
    await stores.statusStore.refresh();
    return stores;
  }

  testWidgets('no Tunnels navigation anywhere in the shell', (tester) async {
    final stores = await healthyStores(tester);
    for (final size in const [
      Size(390, 844),
      Size(700, 1000),
      Size(1280, 900),
    ]) {
      await tester.binding.setSurfaceSize(size);
      addTearDown(() => tester.binding.setSurfaceSize(null));
      await tester.pumpWidget(
        _DesignSystemHost(
          dark: false,
          child: P2WlanShell(
            settingsStore: stores.settingsStore,
            statusStore: stores.statusStore,
            capabilities: PlatformCapabilities.fromPlatform('macos'),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.text('Tunnels'), findsNothing);
      expect(find.byIcon(Icons.cable_outlined), findsNothing);
      if (size.width < 600) {
        expect(
          find.descendant(
            of: find.byType(NavigationBar),
            matching: find.byType(NavigationDestination),
          ),
          findsNWidgets(3),
        );
      }
      expect(tester.takeException(), isNull);
    }
  });

  testWidgets('expanded shell at 1280 shows Troubleshooting with no Tunnels', (
    tester,
  ) async {
    final stores = await healthyStores(tester);
    await pumpShell(tester, const Size(1280, 900), stores: stores);
    expect(find.byType(DesktopSidebar), findsOneWidget);
    expect(find.text('Tunnels'), findsNothing);

    await goToTroubleshooting(tester);

    expect(find.byType(DiagnosticsPage), findsOneWidget);
    expect(find.text('System status'), findsOneWidget);
    expect(find.text('P2WLAN is running normally'), findsOneWidget);
    expect(find.text('Health checks'), findsOneWidget);
    expect(find.text('Advanced diagnostics'), findsOneWidget);
    expect(find.text('Tunnels'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('medium rail at 700 keeps Troubleshooting single-column', (
    tester,
  ) async {
    final stores = await healthyStores(tester);
    await pumpShell(tester, const Size(700, 1000), stores: stores);
    expect(find.byType(AppNavRail), findsOneWidget);
    expect(find.byType(DesktopSidebar), findsNothing);
    expect(find.text('Tunnels'), findsNothing);

    await goToTroubleshooting(tester);

    expect(find.byType(DiagnosticsPage), findsOneWidget);
    expect(find.text('P2WLAN is running normally'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'mobile 390: three tabs, troubleshooting via overflow, no route actions',
    (tester) async {
      final stores = await healthyStores(tester);
      await pumpShell(
        tester,
        const Size(390, 844),
        stores: stores,
        capabilities: PlatformCapabilities.fromPlatform('android'),
      );

      expect(
        find.descendant(
          of: find.byType(NavigationBar),
          matching: find.byType(NavigationDestination),
        ),
        findsNWidgets(3),
      );
      expect(find.text('Tunnels'), findsNothing);

      await goToTroubleshooting(tester);

      expect(find.byType(DiagnosticsPage), findsOneWidget);
      // Advanced stays collapsed and no local-only route action is visible.
      expect(find.text('Advanced diagnostics'), findsOneWidget);
      expect(find.text('Network & routes'), findsNothing);
      expect(find.text('Check routes'), findsNothing);
      expect(find.text('Repair routes'), findsNothing);
      expect(find.text('Restart network service'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('issue action: View devices opens the Devices section', (
    tester,
  ) async {
    final stores = await peerWarningStores(tester);
    await pumpShell(tester, const Size(1280, 900), stores: stores);

    await goToTroubleshooting(tester);

    expect(find.byType(DiagnosticsPage), findsOneWidget);
    expect(find.text('1 device needs path review'), findsOneWidget);
    await tester.ensureVisible(find.text('View devices'));
    await tester.tap(find.text('View devices'));
    await tester.pumpAndSettle();

    expect(find.byType(NodesPage), findsOneWidget);
    expect(find.byType(DiagnosticsPage), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('dark 390 troubleshooting renders and expands cleanly', (
    tester,
  ) async {
    final stores = await healthyStores(tester);
    await tester.binding.setSurfaceSize(const Size(390, 844));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      _DesignSystemHost(
        dark: true,
        child: DiagnosticsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(
      Theme.of(tester.element(find.byType(DiagnosticsPage))).brightness,
      Brightness.dark,
    );
    expect(find.text('P2WLAN is running normally'), findsOneWidget);
    expect(find.text('Health checks'), findsOneWidget);
    await _expandAdvanced(tester);
    expect(find.text('Network & routes'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('dark 1280 troubleshooting renders with advanced expanded', (
    tester,
  ) async {
    final stores = await healthyStores(tester);
    await tester.binding.setSurfaceSize(const Size(1280, 900));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      _DesignSystemHost(
        dark: true,
        child: DiagnosticsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );
    await tester.pumpAndSettle();
    await _expandAdvanced(tester);

    expect(find.text('P2WLAN is running normally'), findsOneWidget);
    expect(find.text('Runtime details'), findsOneWidget);
    expect(find.text('Raw /status JSON'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}
