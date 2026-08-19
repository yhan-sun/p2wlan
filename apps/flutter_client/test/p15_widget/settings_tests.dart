part of '../p15_widget_test.dart';

/// Pumps a desktop-capable settings page wrapped in the test app.
Future<_Stores> _pumpSettings(
  WidgetTester tester, {
  required _FakeDiagnosticsApi api,
  PlatformCapabilities? capabilities,
  VoidCallback? onLogout,
  Size physicalSize = const Size(800, 2400),
}) async {
  tester.view.physicalSize = physicalSize;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  final stores = (await tester.runAsync(() => _makeStores(api: api)))!;
  addTearDown(stores.dispose);
  await tester.pumpWidget(
    _TestApp(
      child: SettingsPage(
        settingsStore: stores.settingsStore,
        statusStore: stores.statusStore,
        capabilities: capabilities,
        onLogout: onLogout,
      ),
    ),
  );
  return stores;
}

Finder _disclosure(String title) =>
    find.byKey(Key('settings-disclosure-$title'));

Finder _settingsTextField(String label) => find.byWidgetPredicate(
  (widget) => widget is TextField && widget.decoration?.labelText == label,
);

/// Waits until [condition] is satisfied or the polling budget is exhausted.
Future<void> _waitFor(WidgetTester tester, bool Function() condition) async {
  for (var attempt = 0; attempt < 30 && !condition(); attempt += 1) {
    await tester.runAsync(
      () => Future<void>.delayed(const Duration(milliseconds: 100)),
    );
    await tester.pump();
  }
}

void _registerSettingsTests() {
  testWidgets('Settings validates diagnostics URL before saving', (
    tester,
  ) async {
    await _pumpSettings(tester, api: _FakeDiagnosticsApi(health: false));

    await tester.tap(_disclosure('Developer & Diagnostics'));
    await tester.pumpAndSettle();
    await tester.enterText(
      _settingsTextField('Diagnostics URL'),
      'ftp://127.0.0.1:39277',
    );
    await tester.tap(find.byKey(const Key('settings-save-button')));
    await tester.pump();

    expect(find.text('Diagnostics URL must use http or https'), findsOneWidget);
    expect(find.text('Diagnostics URL was not saved'), findsOneWidget);
  });

  testWidgets('Settings keeps network fields usable on narrow screens', (
    tester,
  ) async {
    await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: false),
      physicalSize: const Size(390, 1200),
    );

    await tester.ensureVisible(_disclosure('Advanced Network'));
    await tester.pump();
    await tester.tap(_disclosure('Advanced Network'));
    await tester.pumpAndSettle();

    expect(find.text('Interface name'), findsOneWidget);
    expect(find.text('UDP advertise'), findsOneWidget);
    expect(find.text('Manual/offline mode'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets(
    'Settings marks daemon configuration changes as pending restart',
    (tester) async {
      final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
      final stores = await _pumpSettings(
        tester,
        api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      );
      await stores.statusStore.refresh();
      expect(stores.statusStore.daemonReachable, isTrue);

      await tester.tap(_disclosure('Advanced Network'));
      await tester.pumpAndSettle();
      await tester.enterText(_settingsTextField('MTU'), '1280');
      await tester.tap(find.byKey(const Key('settings-save-button')));
      await tester.pump();
      await _waitFor(tester, () => stores.settingsStore.settings.mtu == 1280);
      await _waitFor(
        tester,
        () => find.text('P2WLAN restart required').evaluate().isNotEmpty,
      );

      expect(stores.settingsStore.settings.mtu, 1280);
      expect(find.text('P2WLAN restart required'), findsOneWidget);
      expect(find.text('Restart and apply'), findsOneWidget);
    },
  );

  testWidgets('Credential UI never reveals the stored token', (tester) async {
    tester.view.physicalSize = const Size(800, 2400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final stores = (await tester.runAsync(() async {
      final s = await _makeStores(api: _FakeDiagnosticsApi(health: false));
      await s.settingsStore.updateSettings(
        s.settingsStore.settings.copyWith(authToken: 'secret-token'),
      );
      return s;
    }))!;
    addTearDown(stores.dispose);

    await tester.pumpWidget(
      _TestApp(
        child: SettingsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    // Status is reported, the credential itself is never rendered.
    expect(find.text('Securely saved'), findsOneWidget);
    expect(find.textContaining('secret-token'), findsNothing);
    // The token input is hidden until explicitly requested.
    expect(_settingsTextField('Auth token'), findsNothing);

    await tester.tap(find.text('Change credential'));
    await tester.pump();
    final tokenField = _settingsTextField('Auth token');
    expect(tokenField, findsOneWidget);
    // Always starts empty; the stored token is never prefilled.
    expect(tester.widget<TextField>(tokenField).controller!.text, isEmpty);

    await tester.enterText(tokenField, 'replacement-token');
    await tester.tap(find.byKey(const Key('settings-save-button')));
    await tester.pump();
    await _waitFor(
      tester,
      () => stores.settingsStore.settings.authToken == 'replacement-token',
    );

    expect(stores.settingsStore.settings.authToken, 'replacement-token');
    // The new credential is reported as saved without the token itself ever
    // appearing outside the editable field (which keeps what the user typed).
    expect(find.text('Securely saved'), findsOneWidget);
    expect(
      tester.widget<TextField>(tokenField).controller!.text,
      'replacement-token',
    );
  });

  testWidgets('Empty token save preserves the stored credential', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(800, 2400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final stores = (await tester.runAsync(() async {
      final s = await _makeStores(api: _FakeDiagnosticsApi(health: false));
      await s.settingsStore.updateSettings(
        s.settingsStore.settings.copyWith(authToken: 'kept-token'),
      );
      return s;
    }))!;
    addTearDown(stores.dispose);

    await tester.pumpWidget(
      _TestApp(
        child: SettingsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    await tester.tap(find.text('Change credential'));
    await tester.pump();
    // The revealed token field is empty; save without typing anything.
    await tester.tap(find.byKey(const Key('settings-save-button')));
    await tester.pump();
    await _waitFor(tester, () => !stores.statusStore.refreshing);

    expect(stores.settingsStore.settings.authToken, 'kept-token');
    expect(find.text('Securely saved'), findsOneWidget);
    expect(find.textContaining('kept-token'), findsNothing);
  });

  testWidgets('Settings exposes Sign out only when a handler is provided', (
    tester,
  ) async {
    var signedOut = false;
    await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: false),
      onLogout: () => signedOut = true,
    );

    expect(find.text('Sign out'), findsOneWidget);
    await tester.tap(find.text('Sign out'));
    expect(signedOut, isTrue);
  });

  testWidgets('Settings omits Sign out without a handler', (tester) async {
    await _pumpSettings(tester, api: _FakeDiagnosticsApi(health: false));

    expect(find.text('Sign out'), findsNothing);
  });

  testWidgets('Mobile settings hide local-node and daemon sections', (
    tester,
  ) async {
    await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: false),
      capabilities: PlatformCapabilities.fromPlatform('android'),
      physicalSize: const Size(390, 1200),
    );

    expect(find.text('Advanced Network'), findsNothing);
    expect(find.text('Developer & Diagnostics'), findsNothing);
    expect(find.text('Interface name'), findsNothing);
    expect(find.text('Diagnostics URL'), findsNothing);
    expect(find.text('Close window behavior'), findsNothing);
    // Account-level fields remain available.
    expect(find.text('Control server'), findsOneWidget);
    expect(find.text('Network ID'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Mobile save keeps hidden advanced settings intact', (
    tester,
  ) async {
    tester.view.physicalSize = const Size(390, 1200);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final stores = (await tester.runAsync(() async {
      final s = await _makeStores(api: _FakeDiagnosticsApi(health: false));
      await s.settingsStore.updateSettings(
        s.settingsStore.settings.copyWith(
          tunInterface: 'utun9',
          mtu: 1300,
          overlayCidr: '10.90.0.0/24',
          udpBind: '0.0.0.0:9000',
          udpAdvertise: '203.0.113.9:60207',
          socketPool: '4',
          relayServers: 'relay.example:7000',
        ),
      );
      return s;
    }))!;
    addTearDown(stores.dispose);

    await tester.pumpWidget(
      _TestApp(
        child: SettingsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('android'),
        ),
      ),
    );

    await tester.enterText(
      _settingsTextField('Control server'),
      'https://ctrl.example',
    );
    await tester.tap(find.byKey(const Key('settings-save-button')));
    await tester.pump();
    await _waitFor(
      tester,
      () =>
          stores.settingsStore.settings.controlServer == 'https://ctrl.example',
    );

    final settings = stores.settingsStore.settings;
    expect(settings.controlServer, 'https://ctrl.example');
    expect(settings.tunInterface, 'utun9');
    expect(settings.mtu, 1300);
    expect(settings.overlayCidr, '10.90.0.0/24');
    expect(settings.udpBind, '0.0.0.0:9000');
    expect(settings.udpAdvertise, '203.0.113.9:60207');
    expect(settings.socketPool, '4');
    expect(settings.relayServers, 'relay.example:7000');
  });

  testWidgets('Mobile restart notice never shows a fake restart button', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
      capabilities: PlatformCapabilities.fromPlatform('android'),
    );
    await stores.statusStore.refresh();
    expect(stores.statusStore.daemonReachable, isTrue);

    await tester.enterText(
      _settingsTextField('Control server'),
      'https://ctrl.example',
    );
    await tester.tap(find.byKey(const Key('settings-save-button')));
    await tester.pump();
    await _waitFor(
      tester,
      () => find.text('P2WLAN restart required').evaluate().isNotEmpty,
    );

    expect(find.text('P2WLAN restart required'), findsOneWidget);
    expect(find.text('Restart and apply'), findsNothing);
    expect(
      find.textContaining('next time the relevant node starts'),
      findsOneWidget,
    );
  });

  testWidgets('Language and theme apply immediately without Save', (
    tester,
  ) async {
    final stores = await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: false),
    );

    await tester.tap(find.byKey(const ValueKey('theme-system')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Dark').last);
    await tester.pump();
    await _waitFor(
      tester,
      () => stores.settingsStore.settings.themeMode == 'dark',
    );
    await _waitFor(
      tester,
      () => find.byType(CircularProgressIndicator).evaluate().isEmpty,
    );
    expect(stores.settingsStore.settings.themeMode, 'dark');

    await tester.tap(find.byKey(const ValueKey('language-en')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('简体中文').last);
    await tester.pump();
    await _waitFor(
      tester,
      () => stores.settingsStore.settings.languageCode == 'zh-Hans',
    );
    await _waitFor(
      tester,
      () => find.byType(CircularProgressIndicator).evaluate().isEmpty,
    );
    expect(stores.settingsStore.settings.languageCode, 'zh-Hans');
    expect(find.text('设置'), findsWidgets);
  });

  testWidgets(
    'Settings renders at tablet and desktop widths without overflow',
    (tester) async {
      for (final size in const [Size(700, 1000), Size(1280, 900)]) {
        tester.view.physicalSize = size;
        tester.view.devicePixelRatio = 1;
        final stores = (await tester.runAsync(
          () => _makeStores(api: _FakeDiagnosticsApi(health: false)),
        ))!;
        await tester.pumpWidget(
          _TestApp(
            child: SettingsPage(
              settingsStore: stores.settingsStore,
              statusStore: stores.statusStore,
            ),
          ),
        );
        await tester.ensureVisible(_disclosure('Advanced Network'));
        await tester.pump();
        await tester.tap(_disclosure('Advanced Network'));
        await tester.pumpAndSettle();
        await tester.ensureVisible(_disclosure('Developer & Diagnostics'));
        await tester.pump();
        await tester.tap(_disclosure('Developer & Diagnostics'));
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
        stores.dispose();
      }
      tester.view.resetPhysicalSize();
      tester.view.resetDevicePixelRatio();
    },
  );

  testWidgets('Credential status follows the active language', (tester) async {
    tester.view.physicalSize = const Size(800, 2400);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final stores = (await tester.runAsync(() async {
      final s = await _makeStores(api: _FakeDiagnosticsApi(health: false));
      await s.settingsStore.updateSettings(
        s.settingsStore.settings.copyWith(authToken: 'secret-token'),
      );
      return s;
    }))!;
    addTearDown(stores.dispose);

    await tester.pumpWidget(
      _TestApp(
        child: SettingsPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
        ),
      ),
    );

    expect(find.text('Securely saved'), findsOneWidget);

    // Switch the language without touching Save; the credential status must
    // re-derive from the live store in the new locale.
    await tester.runAsync(
      () => stores.settingsStore.updateLanguageCode('zh-Hans'),
    );
    await tester.pump();

    expect(find.text('已安全保存'), findsOneWidget);
    expect(find.text('Securely saved'), findsNothing);

    // Manual mode is reported from the saved settings, not the draft toggle.
    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(manualMode: true),
      ),
    );
    await tester.pump();

    expect(find.text('手动模式无需凭据'), findsOneWidget);
    expect(find.text('已安全保存'), findsNothing);
  });

  testWidgets('Pending restart survives unrelated saves until applied', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
    );
    await stores.statusStore.refresh();
    expect(stores.statusStore.daemonReachable, isTrue);

    // First save: a real daemon-launch change (MTU) while the daemon runs.
    await tester.tap(_disclosure('Advanced Network'));
    await tester.pumpAndSettle();
    await tester.enterText(_settingsTextField('MTU'), '1280');
    await tester.tap(find.byKey(const Key('settings-save-button')));
    await tester.pump();
    await _waitFor(tester, () => stores.settingsStore.settings.mtu == 1280);
    await _waitFor(
      tester,
      () => find.text('P2WLAN restart required').evaluate().isNotEmpty,
    );
    expect(find.text('P2WLAN restart required'), findsOneWidget);
    expect(find.text('Restart and apply'), findsOneWidget);

    // Second save with no daemon-launch change (close behavior only). The
    // pending restart must NOT be cleared by this unrelated save.
    await tester.ensureVisible(
      find.byKey(const ValueKey('close-behavior-keep-running')),
    );
    await tester.pump();
    await tester.tap(find.byKey(const ValueKey('close-behavior-keep-running')));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Stop P2WLAN').last);
    await tester.pump();
    await _waitFor(
      tester,
      () => find.byType(CircularProgressIndicator).evaluate().isEmpty,
    );
    await tester.tap(find.byKey(const Key('settings-save-button')));
    await tester.pump();
    await _waitFor(
      tester,
      () => stores.settingsStore.settings.closeBehavior == 'stop-and-quit',
    );

    expect(find.text('P2WLAN restart required'), findsOneWidget);
    expect(find.text('Restart and apply'), findsOneWidget);
    expect(stores.settingsStore.settings.closeBehavior, 'stop-and-quit');
    // Wait for the second save (including its refresh) to finish so the
    // restart action is enabled again.
    await _waitFor(
      tester,
      () => find.byType(CircularProgressIndicator).evaluate().isEmpty,
    );

    // Applying the pending restart clears the notice.
    await tester.ensureVisible(find.text('Restart and apply'));
    await tester.pump();
    await tester.tap(find.text('Restart and apply'));
    await tester.pump();
    await _waitFor(
      tester,
      () => find.text('P2WLAN restart required').evaluate().isEmpty,
    );
    expect(find.text('P2WLAN restart required'), findsNothing);
    expect(find.text('Restart and apply'), findsNothing);
  });
}
