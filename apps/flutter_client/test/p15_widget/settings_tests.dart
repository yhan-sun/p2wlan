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
  await tester.pumpAndSettle();
  return stores;
}

Finder _settingsTextField(String label) => find.byWidgetPredicate(
  (widget) => widget is TextField && widget.decoration?.labelText == label,
);

/// Opens a settings category. Works on the medium/compact root-detail layout
/// (taps the root row) and on the desktop rail layout (taps the sidebar item).
/// If a detail is already open it returns to the root first.
Future<void> _openCategory(WidgetTester tester, String label) async {
  if (find.byIcon(Icons.arrow_back_rounded).evaluate().isNotEmpty) {
    await tester.tap(find.byIcon(Icons.arrow_back_rounded));
    await tester.pumpAndSettle();
  }
  final rail = find.byKey(const Key('settings-category-rail'));
  final category = rail.evaluate().isNotEmpty
      ? find.descendant(of: rail, matching: find.text(label))
      : find.text(label);
  await tester.ensureVisible(category);
  await tester.pumpAndSettle();
  await tester.tap(category);
  await tester.pumpAndSettle();
}

/// Taps the save action inside a category detail (it only exists while the
/// category is dirty).
Future<void> _tapSave(WidgetTester tester) async {
  final save = find.byKey(const Key('settings-save-button'));
  expect(save, findsOneWidget);
  await tester.ensureVisible(save);
  await tester.pumpAndSettle();
  await tester.tap(save);
  await tester.pump();
}

/// Waits until [condition] is satisfied or the polling budget is exhausted.
Future<void> _waitFor(WidgetTester tester, bool Function() condition) async {
  for (var attempt = 0; attempt < 30 && !condition(); attempt += 1) {
    await tester.runAsync(
      () => Future<void>.delayed(const Duration(milliseconds: 100)),
    );
    await tester.pump();
  }
}

/// Waits until the immediate-save dropdown at [key] is enabled again, i.e. the
/// previous language/theme persistence fully completed (the in-memory value is
/// set synchronously, before the async disk write finishes).
Future<void> _waitForSaveComplete(WidgetTester tester, Key key) async {
  for (var attempt = 0; attempt < 30; attempt += 1) {
    final trigger = find.descendant(
      of: find.byKey(key),
      matching: find.byType(OutlinedButton),
    );
    if (trigger.evaluate().isNotEmpty &&
        tester.widget<OutlinedButton>(trigger).onPressed != null) {
      return;
    }
    await tester.runAsync(
      () => Future<void>.delayed(const Duration(milliseconds: 100)),
    );
    await tester.pump();
  }
  fail('Immediate-save dropdown never re-enabled for $key');
}

Future<void> _openAppSelect(WidgetTester tester, Key key) async {
  await tester.tap(
    find.descendant(of: find.byKey(key), matching: find.byType(OutlinedButton)),
  );
}

void _registerSettingsTests() {
  testWidgets('Settings validates diagnostics URL before saving', (
    tester,
  ) async {
    await _pumpSettings(tester, api: _FakeDiagnosticsApi(health: false));

    await _openCategory(tester, 'Developer & Diagnostics');
    await tester.enterText(
      _settingsTextField('Diagnostics URL'),
      'ftp://127.0.0.1:39277',
    );
    await tester.pump();
    await _tapSave(tester);

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

    await _openCategory(tester, 'Advanced Network');

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

      await _openCategory(tester, 'Advanced Network');
      await tester.enterText(_settingsTextField('MTU'), '1280');
      await tester.pump();
      await _tapSave(tester);
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
    await tester.pumpAndSettle();

    // Status is reported in the Account & Network detail; the credential
    // itself is never rendered.
    await _openCategory(tester, 'Account & Network');
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
    await tester.pump();
    await _tapSave(tester);
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
    await tester.pumpAndSettle();

    await _openCategory(tester, 'Account & Network');
    await tester.tap(find.text('Change credential'));
    await tester.pump();
    // The revealed token field is empty; save with nothing else changed would
    // be a no-op, so also touch the control server to create a real draft.
    await tester.enterText(
      _settingsTextField('Control server'),
      'https://ctrl.example',
    );
    await tester.pump();
    await _tapSave(tester);
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

    await _openCategory(tester, 'Account & Network');
    expect(find.text('Sign out'), findsOneWidget);
    await tester.tap(find.text('Sign out'));
    expect(signedOut, isTrue);
  });

  testWidgets('Settings omits Sign out without a handler', (tester) async {
    await _pumpSettings(tester, api: _FakeDiagnosticsApi(health: false));

    await _openCategory(tester, 'Account & Network');
    expect(find.text('Sign out'), findsNothing);
  });

  testWidgets('Mobile settings hide local-node and daemon sections', (
    tester,
  ) async {
    await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: false),
      capabilities: PlatformCapabilities.fromPlatform('ios'),
      physicalSize: const Size(390, 1200),
    );

    // Root shows only remote-relevant categories and no technical fields.
    expect(find.text('Advanced Network'), findsNothing);
    expect(find.text('Developer & Diagnostics'), findsNothing);
    expect(find.text('Interface name'), findsNothing);
    expect(find.text('Diagnostics URL'), findsNothing);
    expect(find.text('Close window behavior'), findsNothing);
    expect(find.text('Control server'), findsNothing);

    // Account-level fields remain reachable inside the category detail.
    await _openCategory(tester, 'Account & Network');
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
          capabilities: PlatformCapabilities.fromPlatform('ios'),
        ),
      ),
    );
    await tester.pumpAndSettle();

    await _openCategory(tester, 'Account & Network');
    await tester.enterText(
      _settingsTextField('Control server'),
      'https://ctrl.example',
    );
    await tester.pump();
    await _tapSave(tester);
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
      capabilities: PlatformCapabilities.fromPlatform('ios'),
    );
    await stores.statusStore.refresh();
    expect(stores.statusStore.daemonReachable, isTrue);

    await _openCategory(tester, 'Account & Network');
    await tester.enterText(
      _settingsTextField('Control server'),
      'https://ctrl.example',
    );
    await tester.pump();
    await _tapSave(tester);
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

    await _openCategory(tester, 'General');

    // Immediate settings never trigger the dirty save bar.
    expect(find.text('Unsaved changes'), findsNothing);

    await _openAppSelect(tester, const ValueKey('settings-theme-select'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Dark').last);
    await tester.pump();
    await _waitFor(
      tester,
      () => stores.settingsStore.settings.themeMode == 'dark',
    );
    // The store value is set synchronously before persistence finishes; wait
    // until the save completes (the dropdown re-enables) before the next edit.
    await _waitForSaveComplete(
      tester,
      const ValueKey('settings-language-select'),
    );
    expect(stores.settingsStore.settings.themeMode, 'dark');

    await _openAppSelect(tester, const ValueKey('settings-language-select'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('简体中文').last);
    await tester.pump();
    await _waitFor(
      tester,
      () => stores.settingsStore.settings.languageCode == 'zh-Hans',
    );
    await _waitForSaveComplete(tester, const ValueKey('settings-theme-select'));
    expect(stores.settingsStore.settings.languageCode, 'zh-Hans');
    expect(find.text('设置'), findsWidgets);
    // No connection settings save was triggered by the immediate edits.
    expect(find.text('Unsaved changes'), findsNothing);
  });

  testWidgets(
    'Settings renders at tablet and desktop widths without overflow',
    (tester) async {
      for (final size in const [
        Size(700, 1000),
        Size(1280, 900),
        Size(1440, 900),
      ]) {
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
        await tester.pumpAndSettle();
        await _openCategory(tester, 'Advanced Network');
        await _openCategory(tester, 'Developer & Diagnostics');
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
    await tester.pumpAndSettle();

    // The Account & Network detail carries the credential state on the
    // compact desktop settings layout.
    await _openCategory(tester, 'Account & Network');
    expect(find.text('Securely saved'), findsOneWidget);

    await tester.runAsync(
      () => stores.settingsStore.updateLanguageCode('zh-Hans'),
    );
    await tester.pump();

    expect(find.text('已安全保存'), findsOneWidget);
    expect(find.text('Securely saved'), findsNothing);

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
    await _openCategory(tester, 'Advanced Network');
    await tester.enterText(_settingsTextField('MTU'), '1280');
    await tester.pump();
    await _tapSave(tester);
    await _waitFor(tester, () => stores.settingsStore.settings.mtu == 1280);
    await _waitFor(
      tester,
      () => find.text('P2WLAN restart required').evaluate().isNotEmpty,
    );
    expect(find.text('P2WLAN restart required'), findsOneWidget);
    expect(find.text('Restart and apply'), findsOneWidget);

    // Second save with no daemon-launch change (close behavior only). The
    // pending restart must NOT be cleared by this unrelated save.
    await _openCategory(tester, 'App');
    await _openAppSelect(
      tester,
      const ValueKey('settings-close-behavior-select'),
    );
    await tester.pumpAndSettle();
    await tester.tap(find.text('Stop P2WLAN').last);
    await tester.pump();
    await _waitFor(
      tester,
      () => find.byType(CircularProgressIndicator).evaluate().isEmpty,
    );
    await _tapSave(tester);
    await _waitFor(
      tester,
      () => stores.settingsStore.settings.closeBehavior == 'stop-and-quit',
    );

    expect(find.text('P2WLAN restart required'), findsOneWidget);
    expect(find.text('Restart and apply'), findsOneWidget);
    expect(stores.settingsStore.settings.closeBehavior, 'stop-and-quit');
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
