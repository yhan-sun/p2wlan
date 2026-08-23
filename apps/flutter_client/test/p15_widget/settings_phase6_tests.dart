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

  testWidgets('android: Settings detail is full-screen and back unwinds', (
    tester,
  ) async {
    final stores = await _pumpSettingsShell(
      tester,
      const Size(360, 800),
      capabilities: PlatformCapabilities.fromPlatform('android'),
      dark: true,
    );
    addTearDown(stores.dispose);

    debugDefaultTargetPlatformOverride = TargetPlatform.android;
    try {
      // The settings root is a primary destination with the normal shell.
      expect(find.byType(NavigationBar), findsOneWidget);
      expect(find.text('General'), findsOneWidget);

      await tester.tap(find.text('General'));
      await tester.pumpAndSettle();

      // A real route covers both pieces of parent chrome from the screenshot:
      // the shell app bar/overflow and the persistent bottom navigation.
      expect(
        find.byKey(const Key('settings-mobile-category-page')),
        findsOneWidget,
      );
      expect(
        find.byKey(const Key('settings-mobile-category-app-bar')),
        findsOneWidget,
      );
      expect(
        find.byKey(const Key('settings-mobile-category-back')),
        findsOneWidget,
      );
      expect(find.byType(NavigationBar), findsNothing);
      expect(find.byIcon(Icons.more_horiz_rounded), findsNothing);
      expect(find.text('Device name'), findsOneWidget);

      // Select controls use the mobile product sheet, not a stock popup.
      final languageSelect = find.byKey(
        const ValueKey('settings-language-select'),
      );
      expect(MediaQuery.sizeOf(tester.element(languageSelect)).width, 360);
      expect(defaultTargetPlatform, TargetPlatform.android);
      await _openAppSelect(tester, const ValueKey('settings-language-select'));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('app-select-mobile-sheet')), findsOneWidget);
      expect(
        find.descendant(
          of: find.byKey(const Key('app-select-mobile-sheet')),
          matching: find.text('Language'),
        ),
        findsOneWidget,
      );

      // Back closes exactly one layer at a time: selector, category, Settings.
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('app-select-mobile-sheet')), findsNothing);
      expect(
        find.byKey(const Key('settings-mobile-category-page')),
        findsOneWidget,
      );

      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(
        find.byKey(const Key('settings-mobile-category-page')),
        findsNothing,
      );
      expect(find.byType(SettingsPage), findsOneWidget);
      expect(find.byType(NavigationBar), findsOneWidget);
      expect(find.text('General'), findsOneWidget);

      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(find.byType(DashboardPage), findsOneWidget);
      expect(find.byType(P2WlanShell), findsOneWidget);
      expect(tester.takeException(), isNull);
    } finally {
      debugDefaultTargetPlatformOverride = null;
    }
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

    await _openAppSelect(tester, const ValueKey('settings-theme-select'));
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

  // -- Phase 6.1: manual-mode credential semantics regression tests --

  testWidgets('manual mode: enabling clears existing managed credential', (
    tester,
  ) async {
    final repo = InMemorySecureTokenRepository();
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: false),
        tokenRepository: repo,
      ),
    ))!;
    addTearDown(stores.dispose);
    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(authToken: 'existing-secret'),
      ),
    );
    expect(
      (await repo.read())?.isNotEmpty ?? false,
      isTrue,
      reason: 'Precondition: credential should be stored.',
    );

    await pump(tester, stores, size: const Size(800, 2400));

    await tester.tap(find.text('Advanced Network'));
    await tester.pumpAndSettle();

    final manualSwitch = find.byType(Switch).first;
    expect(tester.widget<Switch>(manualSwitch).value, isFalse);
    await tester.tap(manualSwitch);
    await tester.pump();
    expect(find.text('Unsaved changes'), findsOneWidget);
    await _tapSave(tester);
    await _waitFor(tester, () => stores.settingsStore.settings.manualMode);

    expect(stores.settingsStore.settings.manualMode, isTrue);
    expect(stores.settingsStore.settings.authToken, isEmpty);
    final secureValue = await tester.runAsync(() => repo.read());
    expect(
      secureValue,
      isNull,
      reason: 'Manual mode must clear the secure credential store.',
    );
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'advanced network save with manual off preserves existing credential',
    (tester) async {
      final repo = InMemorySecureTokenRepository();
      final stores = (await tester.runAsync(
        () => _makeStores(
          api: _FakeDiagnosticsApi(health: false),
          tokenRepository: repo,
        ),
      ))!;
      addTearDown(stores.dispose);
      await tester.runAsync(
        () => stores.settingsStore.updateSettings(
          stores.settingsStore.settings.copyWith(authToken: 'existing-secret'),
        ),
      );

      await pump(tester, stores, size: const Size(800, 2400));

      await tester.tap(find.text('Advanced Network'));
      await tester.pumpAndSettle();

      final manualSwitch = find.byType(Switch).first;
      expect(tester.widget<Switch>(manualSwitch).value, isFalse);
      await tester.enterText(_settingsTextField('MTU'), '1400');
      await tester.pump();
      expect(find.text('Unsaved changes'), findsOneWidget);
      await _tapSave(tester);
      await _waitFor(tester, () => stores.settingsStore.settings.mtu == 1400);

      expect(stores.settingsStore.settings.manualMode, isFalse);
      expect(stores.settingsStore.settings.authToken, 'existing-secret');
      expect(await tester.runAsync(() => repo.read()), 'existing-secret');
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('manual mode toggle while daemon running requires restart', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = await storesWith(
      tester,
      _FakeDiagnosticsApi(health: true, snapshot: snapshot),
    );
    await pump(tester, stores, size: const Size(800, 2400));
    await stores.statusStore.refresh();
    expect(stores.statusStore.daemonReachable, isTrue);

    await tester.tap(find.text('Advanced Network'));
    await tester.pumpAndSettle();

    final manualSwitch = find.byType(Switch).first;
    await tester.tap(manualSwitch);
    await tester.pump();
    await _tapSave(tester);
    await _waitFor(tester, () => stores.settingsStore.settings.manualMode);
    await _waitFor(
      tester,
      () => find.text('P2WLAN restart required').evaluate().isNotEmpty,
    );

    expect(stores.settingsStore.settings.manualMode, isTrue);
    expect(find.text('P2WLAN restart required'), findsOneWidget);
    expect(find.text('Restart and apply'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'credential summary shows Manual mode after enabling manual mode save',
    (tester) async {
      final repo = InMemorySecureTokenRepository();
      final stores = (await tester.runAsync(
        () => _makeStores(
          api: _FakeDiagnosticsApi(health: false),
          tokenRepository: repo,
        ),
      ))!;
      addTearDown(stores.dispose);
      await tester.runAsync(
        () => stores.settingsStore.updateSettings(
          stores.settingsStore.settings.copyWith(authToken: 'existing-secret'),
        ),
      );

      await pump(tester, stores, size: const Size(800, 2400));

      expect(find.text('Securely saved'), findsOneWidget);

      await tester.tap(find.text('Advanced Network'));
      await tester.pumpAndSettle();

      final manualSwitch = find.byType(Switch).first;
      await tester.tap(manualSwitch);
      await tester.pump();
      await _tapSave(tester);
      await _waitFor(tester, () => stores.settingsStore.settings.manualMode);

      // Return to the settings root to check the Account credential summary.
      await tester.tap(find.byIcon(Icons.arrow_back_rounded));
      await tester.pumpAndSettle();

      expect(find.text('Manual mode, no credential needed'), findsOneWidget);
      expect(find.text('Securely saved'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );
}

/// Pumps the full shell (rail/sidebar/bottom-nav) with healthy diagnostics so
/// Settings can be exercised at real window widths.
///
/// When [capabilities] indicate a mobile platform (no local daemon control),
/// [debugDefaultTargetPlatformOverride] is set so the shell renders the mobile
/// bottom-nav layout. The override is reset before returning — the shell's
/// widget tree is already built with the correct platform, and subsequent
/// `find`/`tap` calls will still locate the mobile widgets that were built
/// during the pump. Tests that need to *re-pump* with a mobile platform
/// should set the override themselves.
///
/// When [textScale] > 1.0, wraps the shell in a [MediaQuery] with a linear
/// text scaler to exercise large-text accessibility at initial pump time, so
/// the platform override, capabilities, and navigation state are all
/// consistent — no re-pump is needed.
Future<_Stores> _pumpSettingsShell(
  WidgetTester tester,
  Size size, {
  PlatformCapabilities? capabilities,
  double textScale = 1.0,
  bool dark = false,
}) async {
  // Reset the element tree so a previous pump's shell state (section /
  // selected category) does not leak into this new shell instance.
  await tester.pumpWidget(const SizedBox.shrink());
  tester.view.physicalSize = size;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  await tester.binding.setSurfaceSize(size);
  addTearDown(() => tester.binding.setSurfaceSize(null));

  final caps = capabilities ?? PlatformCapabilities.fromPlatform('macos');
  final isMobilePlatform = !caps.canUseSystemTray;
  if (isMobilePlatform) {
    // Infer android vs iOS from the size — android tests use 360 width,
    // iOS tests use 390 width. Both produce identical capabilities, so
    // the platform is inferred from the test's viewport size.
    debugDefaultTargetPlatformOverride = size.width < 375
        ? TargetPlatform.android
        : TargetPlatform.iOS;
  }

  final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
  final clean = _mutateSnapshot(snapshot, _clearPeerErrors);
  final stores = (await tester.runAsync(
    () => _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: clean)),
  ))!;
  await stores.statusStore.refresh();
  Widget shell = P2WlanShell(
    settingsStore: stores.settingsStore,
    statusStore: stores.statusStore,
    capabilities: caps,
  );
  if (textScale != 1.0) {
    final unscaledShell = shell;
    shell = Builder(
      builder: (context) => MediaQuery(
        data: MediaQuery.of(
          context,
        ).copyWith(textScaler: TextScaler.linear(textScale)),
        child: unscaledShell,
      ),
    );
  }
  await tester.pumpWidget(_DesignSystemHost(dark: dark, child: shell));
  await tester.pumpAndSettle();
  // Navigate to Settings (sidebar on expanded, rail on medium, bottom bar
  // on compact mobile).
  final sidebar = find.descendant(
    of: find.byType(DesktopSidebar),
    matching: find.text('Settings'),
  );
  final rail = find.descendant(
    of: find.byType(AppNavRail),
    matching: find.text('Settings'),
  );
  final bottom = find.descendant(
    of: find.byType(NavigationBar),
    matching: find.text('Settings'),
  );
  final target = sidebar.evaluate().isNotEmpty
      ? sidebar
      : rail.evaluate().isNotEmpty
      ? rail
      : bottom;
  expect(target, findsOneWidget);
  await tester.tap(target);
  await tester.pumpAndSettle();

  // Reset if we set it (mobile platforms). The framework's
  // _verifyInvariants asserts that foundation debug variables are unset
  // before it runs addTearDown callbacks.
  if (isMobilePlatform) {
    debugDefaultTargetPlatformOverride = null;
  }

  return stores;
}
