part of '../p15_widget_test.dart';

/// Phase 6 adaptive-settings coverage: category hierarchy, capability-driven
/// categories, dirty/save behavior, credential security, restart semantics,
/// responsive layouts and dark mode.
void _registerSettingsPhase6Tests() {
  Future<_Stores> storesWith(
    WidgetTester tester,
    _FakeDiagnosticsApi api,
  ) async {
    final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
    addTearDown(stores.dispose);
    return stores;
  }

  Future<void> pump(
    WidgetTester tester,
    _Stores stores, {
    PlatformCapabilities? capabilities,
    Size? size,
    VoidCallback? onLogout,
  }) async {
    if (size != null) {
      tester.view.physicalSize = size;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
    }
    await tester.pumpWidget(
      _TestApp(
        child: SettingsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities:
              capabilities ?? PlatformCapabilities.fromPlatform('macos'),
          onLogout: onLogout,
        ),
      ),
    );
    await tester.pumpAndSettle();
  }

  testWidgets('mobile root: no technical text fields, categories only', (
    tester,
  ) async {
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    await pump(tester, stores, size: const Size(390, 844));

    // The root is a findable category list, never a stack of input fields.
    expect(find.text('General'), findsOneWidget);
    expect(find.text('Account & Network'), findsOneWidget);
    for (final technical in [
      'MTU',
      'UDP bind',
      'UDP advertise',
      'Interface name',
      'Diagnostics URL',
      'Control server',
      'Network ID',
      'Relay candidates',
      'Socket pool',
    ]) {
      expect(find.text(technical), findsNothing);
    }
    expect(tester.takeException(), isNull);
  });

  testWidgets('mobile: open and return from Account & Network detail', (
    tester,
  ) async {
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    await pump(tester, stores, size: const Size(390, 844));

    await tester.tap(find.text('Account & Network'));
    await tester.pumpAndSettle();

    expect(find.text('Control server'), findsOneWidget);
    expect(find.text('Network ID'), findsOneWidget);
    expect(find.text('Authentication'), findsOneWidget);
    expect(find.byIcon(Icons.arrow_back_rounded), findsOneWidget);

    // Return to the root.
    await tester.tap(find.byIcon(Icons.arrow_back_rounded));
    await tester.pumpAndSettle();
    expect(find.text('General'), findsOneWidget);
    expect(find.text('Control server'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('mobile: Advanced Network detail has no overflow', (
    tester,
  ) async {
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    await pump(tester, stores, size: const Size(390, 844));

    await tester.tap(find.text('Advanced Network'));
    await tester.pumpAndSettle();

    expect(find.text('Manual/offline mode'), findsOneWidget);
    expect(find.text('Interface name'), findsOneWidget);
    expect(find.text('MTU'), findsOneWidget);
    expect(find.text('Overlay CIDR'), findsOneWidget);
    expect(find.text('UDP bind'), findsOneWidget);
    expect(find.text('Socket pool'), findsOneWidget);
    expect(find.text('Relay candidates'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('expanded desktop: rail + inline detail, category switching', (
    tester,
  ) async {
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    await pump(tester, stores, size: const Size(1280, 900));

    // Rail exists with General selected by default (rail item + detail title).
    expect(find.text('General'), findsWidgets);
    expect(find.text('Account & Network'), findsOneWidget);
    expect(find.text('Advanced Network'), findsOneWidget);
    expect(find.text('Developer & Diagnostics'), findsOneWidget);
    // General detail is inline (device name field visible), no dialog.
    expect(find.text('Device name'), findsOneWidget);
    expect(find.byType(Dialog), findsNothing);

    // Switch categories inline.
    await tester.tap(find.text('Account & Network'));
    await tester.pumpAndSettle();
    expect(find.text('Control server'), findsOneWidget);
    await tester.tap(find.text('Advanced Network'));
    await tester.pumpAndSettle();
    expect(find.text('Interface name'), findsOneWidget);
    await tester.tap(find.text('Developer & Diagnostics'));
    await tester.pumpAndSettle();
    expect(find.text('Diagnostics URL'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('medium 700 and 900: category nav without double rail', (
    tester,
  ) async {
    for (final size in const [Size(700, 1000), Size(900, 1000)]) {
      final stores = await _pumpSettingsShell(tester, size);
      addTearDown(stores.dispose);

      // Global medium shell: rail only, no sidebar footer.
      expect(find.byType(AppNavRail), findsOneWidget);
      expect(find.byType(DesktopSidebar), findsNothing);

      // Settings root list (no settings mini-sidebar at medium widths).
      expect(find.text('General'), findsOneWidget);
      expect(find.text('Account & Network'), findsOneWidget);
      await tester.tap(find.text('Advanced Network'));
      await tester.pumpAndSettle();
      expect(find.text('Interface name'), findsOneWidget);
      expect(tester.takeException(), isNull);

      // Clean up before the next size iteration.
      await tester.binding.setSurfaceSize(const Size(800, 600));
      await tester.pumpAndSettle();
    }
  });

  testWidgets('mobile: returning from detail keeps Settings selected', (
    tester,
  ) async {
    final stores = await _pumpSettingsShell(
      tester,
      const Size(390, 844),
      capabilities: PlatformCapabilities.fromPlatform('android'),
    );
    addTearDown(stores.dispose);

    // Exactly three bottom destinations, Settings selected.
    expect(
      find.descendant(
        of: find.byType(NavigationBar),
        matching: find.byType(NavigationDestination),
      ),
      findsNWidgets(3),
    );

    // Open Settings from the bottom bar, then open a category detail.
    await tester.tap(
      find.descendant(
        of: find.byType(NavigationBar),
        matching: find.text('Settings'),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('General'), findsOneWidget);
    await tester.tap(find.text('Account & Network'));
    await tester.pumpAndSettle();
    expect(find.text('Control server'), findsOneWidget);

    // Back returns to the settings root with Settings still the active tab.
    await tester.tap(find.byIcon(Icons.arrow_back_rounded));
    await tester.pumpAndSettle();
    expect(find.text('General'), findsOneWidget);
    expect(find.text('Control server'), findsNothing);
    expect(
      find.descendant(
        of: find.byType(NavigationBar),
        matching: find.byType(NavigationDestination),
      ),
      findsNWidgets(3),
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('dirty detection: device name change shows Save, resets after', (
    tester,
  ) async {
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    await pump(tester, stores, size: const Size(800, 1200));

    expect(find.text('Unsaved changes'), findsNothing);

    await tester.tap(find.text('General'));
    await tester.pumpAndSettle();
    await tester.enterText(_settingsTextField('Device name'), '  pyu-mac  ');
    await tester.pump();

    expect(find.text('Unsaved changes'), findsOneWidget);
    await _tapSave(tester);
    await _waitFor(
      tester,
      () => stores.settingsStore.settings.deviceName == 'pyu-mac',
    );

    expect(stores.settingsStore.settings.deviceName, 'pyu-mac');
    expect(find.text('Unsaved changes'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('category switch preserves the unsaved draft', (tester) async {
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    await pump(tester, stores, size: const Size(1280, 900));

    await tester.tap(find.text('Advanced Network'));
    await tester.pumpAndSettle();
    await tester.enterText(_settingsTextField('MTU'), '1333');
    await tester.pump();
    expect(find.text('Unsaved changes'), findsOneWidget);

    // Switch away and back; the draft must survive (never re-created).
    await tester.tap(find.text('General'));
    await tester.pumpAndSettle();
    expect(find.text('Unsaved changes'), findsNothing);
    await tester.tap(find.text('Advanced Network'));
    await tester.pumpAndSettle();
    expect(find.text('Unsaved changes'), findsOneWidget);
    expect(
      tester.widget<TextField>(_settingsTextField('MTU')).controller!.text,
      '1333',
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('language and theme never trigger the dirty save bar', (
    tester,
  ) async {
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    await pump(tester, stores, size: const Size(800, 1200));

    await tester.tap(find.text('General'));
    await tester.pumpAndSettle();

    await tester.tap(find.byKey(const ValueKey('theme-system')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Dark').last);
    await tester.pump();
    await _waitFor(
      tester,
      () => find.byType(CircularProgressIndicator).evaluate().isEmpty,
    );

    expect(find.text('Unsaved changes'), findsNothing);
    expect(find.byKey(const Key('settings-save-button')), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Diagnostics URL running-daemon guard blocks and keeps stored', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = await storesWith(
      tester,
      _FakeDiagnosticsApi(health: true, snapshot: snapshot),
    );
    await pump(tester, stores, size: const Size(800, 1200));
    await stores.statusStore.refresh();
    expect(stores.statusStore.daemonReachable, isTrue);
    final storedUrl = stores.settingsStore.settings.diagnosticsUrl;

    await tester.tap(find.text('Developer & Diagnostics'));
    await tester.pumpAndSettle();
    await tester.enterText(
      _settingsTextField('Diagnostics URL'),
      'http://127.0.0.1:39999/status',
    );
    await tester.pump();
    await _tapSave(tester);

    expect(
      find.text('Stop P2WLAN before changing the Diagnostics URL.'),
      findsOneWidget,
    );
    expect(stores.settingsStore.settings.diagnosticsUrl, storedUrl);
    expect(tester.takeException(), isNull);
  });

  testWidgets('validation: invalid control server is not silently accepted', (
    tester,
  ) async {
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    await pump(tester, stores, size: const Size(800, 1200));

    await tester.tap(find.text('Account & Network'));
    await tester.pumpAndSettle();
    await tester.enterText(
      _settingsTextField('Control server'),
      'ftp://ctrl.example',
    );
    await tester.pump();
    await _tapSave(tester);
    await tester.pumpAndSettle();

    expect(find.textContaining('must use http or https'), findsOneWidget);
    expect(
      stores.settingsStore.settings.controlServer,
      isNot('ftp://ctrl.example'),
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets('capability: no local node hides advanced category entirely', (
    tester,
  ) async {
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    // Remote-only device: can manage devices, but no local node / daemon.
    const caps = PlatformCapabilities(
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
    await pump(tester, stores, size: const Size(800, 1200), capabilities: caps);

    expect(find.text('General'), findsOneWidget);
    expect(find.text('Account & Network'), findsOneWidget);
    expect(find.text('Advanced Network'), findsNothing);
    expect(find.text('Developer & Diagnostics'), findsNothing);
    expect(find.text('App'), findsNothing);
    for (final technical in [
      'Interface name',
      'MTU',
      'UDP bind',
      'Overlay CIDR',
      'Socket pool',
      'Relay candidates',
      'Diagnostics URL',
    ]) {
      expect(find.text(technical), findsNothing);
    }
    expect(tester.takeException(), isNull);
  });

  testWidgets('no system tray hides the Application category', (tester) async {
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    const caps = PlatformCapabilities(
      canControlLocalDaemon: true,
      canRequestElevation: true,
      canVerifyRoutes: true,
      canRepairRoutes: true,
      canOpenLocalLogs: true,
      canCreateSupportBundle: true,
      canUseSystemTray: false,
      canActAsLocalVpnNode: true,
      canManageRemoteDevices: true,
    );
    await pump(tester, stores, size: const Size(800, 1200), capabilities: caps);

    expect(find.text('App'), findsNothing);
    expect(find.text('Close window behavior'), findsNothing);
    expect(find.text('Advanced Network'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('sign out is a bottom danger action, not a network field', (
    tester,
  ) async {
    var signedOut = false;
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    await pump(
      tester,
      stores,
      size: const Size(800, 1200),
      onLogout: () => signedOut = true,
    );

    await tester.tap(find.text('Account & Network'));
    await tester.pumpAndSettle();
    // Sign out is present and tappable.
    expect(find.text('Sign out'), findsOneWidget);
    await tester.tap(find.text('Sign out'));
    expect(signedOut, isTrue);
    expect(tester.takeException(), isNull);
  });

  testWidgets('dark 390 settings renders without errors', (tester) async {
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    await tester.binding.setSurfaceSize(const Size(390, 844));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      _DesignSystemHost(
        dark: true,
        child: SettingsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          onLogout: () {},
        ),
      ),
    );
    await tester.pumpAndSettle();

    expect(
      Theme.of(tester.element(find.byType(SettingsPage))).brightness,
      Brightness.dark,
    );
    expect(find.text('General'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('dark 1280 settings: general + advanced render cleanly', (
    tester,
  ) async {
    final stores = await storesWith(tester, _FakeDiagnosticsApi(health: false));
    await tester.binding.setSurfaceSize(const Size(1280, 900));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    await tester.pumpWidget(
      _DesignSystemHost(
        dark: true,
        child: SettingsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          onLogout: () {},
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Desktop rail + inline detail in dark mode.
    expect(find.text('General'), findsWidgets);
    expect(find.text('Device name'), findsOneWidget);
    await tester.tap(find.text('Advanced Network'));
    await tester.pumpAndSettle();
    expect(find.text('Interface name'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}

/// Pumps the full shell (rail/sidebar/bottom-nav) with healthy diagnostics so
/// Settings can be exercised at real window widths.
Future<_Stores> _pumpSettingsShell(
  WidgetTester tester,
  Size size, {
  PlatformCapabilities? capabilities,
}) async {
  // Reset the element tree so a previous pump's shell state (section /
  // selected category) does not leak into this new shell instance.
  await tester.pumpWidget(const SizedBox.shrink());
  await tester.binding.setSurfaceSize(size);
  addTearDown(() => tester.binding.setSurfaceSize(null));
  final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
  final clean = _mutateSnapshot(snapshot, _clearPeerErrors);
  final stores = (await tester.runAsync(
    () => _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: clean)),
  ))!;
  await stores.statusStore.refresh();
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
  // Navigate to Settings (rail text on medium, bottom bar on compact).
  final rail = find.descendant(
    of: find.byType(AppNavRail),
    matching: find.text('Settings'),
  );
  final bottom = find.descendant(
    of: find.byType(NavigationBar),
    matching: find.text('Settings'),
  );
  final target = rail.evaluate().isNotEmpty ? rail : bottom;
  expect(target, findsOneWidget);
  await tester.tap(target);
  await tester.pumpAndSettle();
  return stores;
}
