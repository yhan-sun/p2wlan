part of '../p15_widget_test.dart';

/// Pumps a desktop-capable settings page wrapped in the test app.
Future<_Stores> _pumpSettings(
  WidgetTester tester, {
  required _FakeDiagnosticsApi api,
  PlatformCapabilities? capabilities,
  VoidCallback? onLogout,
  VoidCallback? onReauthenticate,
  ValueChanged<bool>? onDirtyChanged,
  SecureTokenRepository? tokenRepository,
  UpdateService? updateService,
  DaemonController? daemonController,
  Size physicalSize = const Size(800, 2400),
}) async {
  tester.view.physicalSize = physicalSize;
  tester.view.devicePixelRatio = 1;
  addTearDown(tester.view.resetPhysicalSize);
  addTearDown(tester.view.resetDevicePixelRatio);
  final stores = (await tester.runAsync(
    () => _makeStores(
      api: api,
      tokenRepository: tokenRepository,
      daemonController: daemonController,
    ),
  ))!;
  addTearDown(stores.dispose);
  final page = SettingsPage(
    settingsStore: stores.settingsStore,
    statusStore: stores.statusStore,
    capabilities: capabilities,
    onLogout: onLogout,
    onReauthenticate: onReauthenticate,
    onDirtyChanged: onDirtyChanged,
    updateService: updateService,
  );
  await tester.pumpWidget(_TestApp(child: page));
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
  if (find.byKey(const Key('settings-category-back')).evaluate().isNotEmpty) {
    await tester.tap(find.byKey(const Key('settings-category-back')));
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
/// previous language/theme persistence and its UI feedback fully completed.
Future<void> _waitForSaveComplete(WidgetTester tester, Key key) async {
  for (var attempt = 0; attempt < 30; attempt += 1) {
    final widget = tester.widget(find.byKey(key));
    if (widget is SegmentedButton<String> &&
        widget.onSelectionChanged != null) {
      return;
    }
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
  await tester.ensureVisible(find.byKey(key));
  await tester.pumpAndSettle();
  if (tester.widget(find.byKey(key)) is SegmentedButton<String>) return;
  await tester.tap(
    find.descendant(of: find.byKey(key), matching: find.byType(OutlinedButton)),
  );
}

void _registerSettingsTests() {
  testWidgets('Settings entry rows show useful summaries and all fit a phone', (
    tester,
  ) async {
    final stores = await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: false),
      capabilities: PlatformCapabilities.fromPlatform('macos'),
      physicalSize: const Size(390, 844),
    );
    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(
          accountUsername: 'River',
          themeMode: 'dark',
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('English · Dark'), findsOneWidget);
    expect(find.text('River · control.example.com'), findsOneWidget);
    expect(find.text('Defaults · Automatic connection path'), findsOneWidget);
    final buildVersion = stores
        .statusStore
        .daemonController
        .clientBuildInfo
        .appVersion
        .trim();
    final unavailableVersion =
        buildVersion.isEmpty || buildVersion.toLowerCase() == 'unknown';
    expect(
      find.text(
        '${unavailableVersion ? 'Version unavailable' : buildVersion} · Not checked',
      ),
      findsOneWidget,
    );
    expect(find.text('unknown · Not checked'), findsNothing);
    final first = find.byKey(const ValueKey('settings-category-card-general'));
    final last = find.byKey(const ValueKey('settings-category-card-developer'));
    expect(first.hitTestable(), findsOneWidget);
    expect(last.hitTestable(), findsOneWidget);
    expect(tester.getSize(first).height, lessThan(100));
    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(mtu: 1280),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('Custom settings · MTU 1280'), findsOneWidget);
    await tester.runAsync(
      () => stores.settingsStore.updateLanguageCode('zh-Hans'),
    );
    await tester.pumpAndSettle();
    expect(
      find.text('${unavailableVersion ? '版本未知' : buildVersion} · 未检查'),
      findsOneWidget,
    );
    await _openCategory(tester, '诊断与关于');
    expect(
      find.text(unavailableVersion ? '版本未知' : buildVersion),
      findsOneWidget,
    );
    if (unavailableVersion) expect(find.text('unknown'), findsNothing);
  });

  testWidgets(
    'Settings puts appearance first and keeps a narrow switch beside its label',
    (tester) async {
      await _pumpSettings(
        tester,
        api: _FakeDiagnosticsApi(health: false),
        capabilities: PlatformCapabilities.fromPlatform('macos'),
        physicalSize: const Size(390, 844),
      );
      await _openCategory(tester, 'General');
      expect(
        tester
            .getTopLeft(find.byKey(const ValueKey('settings-language-select')))
            .dy,
        lessThan(tester.getTopLeft(_settingsTextField('Device name')).dy),
      );
      final toggle = find.byKey(
        const ValueKey('settings-start-at-login-switch'),
      );
      await tester.ensureVisible(toggle);
      await tester.pumpAndSettle();
      expect(
        tester.getCenter(toggle).dy,
        closeTo(tester.getCenter(find.text('Launch P2WLAN at login')).dy, 1),
      );
      expect(
        tester
            .getTopLeft(
              find.text(
                'Launch at desktop sign-in and connect when your account and device are ready.',
              ),
            )
            .dy,
        greaterThan(
          tester.getBottomRight(find.text('Launch P2WLAN at login')).dy,
        ),
      );
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'Settings shows one pending notice when a completed restart is still unconfirmed',
    (tester) async {
      final source = (await tester.runAsync(_loadFixtureSnapshot))!;
      final snapshot = _mutateSnapshot(source, (raw) {
        raw['process_id'] = null;
        raw['runtime_incarnation'] = null;
        return raw;
      });
      final api = _FakeDiagnosticsApi(health: true, snapshot: snapshot);
      final stores = await _pumpSettings(tester, api: api);
      await stores.statusStore.refresh();
      await tester.runAsync(
        () => stores.settingsStore.updateSettings(
          stores.settingsStore.settings.copyWith(mtu: 1280),
        ),
      );
      await tester.pumpAndSettle();
      await _openCategory(tester, 'General');
      await _tapVisible(tester, find.text('Restart and apply'));
      await _waitFor(tester, () => !stores.statusStore.daemonBusy);
      expect(stores.statusStore.primaryConfigurationPending, isTrue);
      expect(find.text('P2WLAN restart required'), findsOneWidget);
      expect(
        find.byKey(const ValueKey('local-connection-restart-feedback')),
        findsNothing,
      );
      expect(find.text('Restart and apply'), findsOneWidget);
    },
  );

  testWidgets('Settings validates diagnostics URL before saving', (
    tester,
  ) async {
    await _pumpSettings(tester, api: _FakeDiagnosticsApi(health: false));

    await _openCategory(tester, 'Diagnostics & About');
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
    expect(find.text('Manual/offline mode'), findsNothing);
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

    // Status is reported in the Account & Connection detail; the credential
    // itself is never rendered.
    await _openCategory(tester, 'Account & Connection');
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

    await _waitFor(
      tester,
      () => find.byKey(const Key('settings-save-button')).evaluate().isEmpty,
    );
    expect(stores.settingsStore.settings.authToken, 'replacement-token');
    // The new credential is reported as saved without the token itself ever
    // appearing outside the editable field (which keeps what the user typed).
    expect(find.text('Securely saved'), findsOneWidget);
    expect(tester.widget<TextField>(tokenField).controller!.text, isEmpty);
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

    await _openCategory(tester, 'Account & Connection');
    await tester.tap(find.text('Change credential'));
    await tester.pump();
    // The revealed token field is empty; save with nothing else changed would
    // be a no-op, so edit the network while retaining the credential's server.
    await tester.enterText(_settingsTextField('Network ID'), 'test-network');
    await tester.pump();
    await _tapSave(tester);
    await _waitFor(
      tester,
      () => find.byKey(const Key('settings-save-button')).evaluate().isEmpty,
    );

    expect(stores.settingsStore.settings.networkId, 'test-network');
    expect(stores.settingsStore.settings.authToken, 'kept-token');
    expect(find.text('Securely saved'), findsOneWidget);
    expect(find.textContaining('kept-token'), findsNothing);
  });

  testWidgets(
    'Server change requires an explicit new credential before saving',
    (tester) async {
      final stores = await _pumpSettings(
        tester,
        api: _FakeDiagnosticsApi(health: false),
      );
      await tester.runAsync(
        () => stores.settingsStore.updateSettings(
          stores.settingsStore.settings.copyWith(authToken: 'original-token'),
        ),
      );
      await tester.pumpAndSettle();
      await _openCategory(tester, 'Account & Connection');
      await tester.enterText(
        _settingsTextField('Control server'),
        'https://new.example.com',
      );
      await tester.pump();
      await _tapSave(tester);
      await tester.pumpAndSettle();
      expect(find.textContaining('Sign in to the new server'), findsOneWidget);
      expect(
        stores.settingsStore.settings.controlServer,
        'https://control.example.com',
      );
      expect(stores.settingsStore.settings.authToken, 'original-token');
      expect(
        await tester.runAsync(stores.tokenRepository.read),
        'original-token',
      );
      expect(
        tester
            .widget<TextField>(_settingsTextField('Control server'))
            .controller!
            .text,
        'https://new.example.com',
      );
      expect(find.byKey(const Key('settings-save-button')), findsOneWidget);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets('Settings exposes Sign out only when a handler is provided', (
    tester,
  ) async {
    var signedOut = false;
    await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: false),
      onLogout: () => signedOut = true,
    );

    await _openCategory(tester, 'Account & Connection');
    expect(find.text('Sign out'), findsOneWidget);
    await tester.tap(find.text('Sign out'));
    expect(signedOut, isTrue);
  });

  testWidgets('Settings omits Sign out without a handler', (tester) async {
    await _pumpSettings(tester, api: _FakeDiagnosticsApi(health: false));

    await _openCategory(tester, 'Account & Connection');
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
    expect(find.text('Diagnostics & About'), findsOneWidget);
    expect(find.text('Interface name'), findsNothing);
    expect(find.text('Diagnostics URL'), findsNothing);
    expect(find.text('Close window behavior'), findsNothing);
    expect(find.text('Control server'), findsNothing);

    // Account-level fields remain reachable inside the category detail.
    await _openCategory(tester, 'Account & Connection');
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

    await _openCategory(tester, 'Account & Connection');
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

    await _openCategory(tester, 'Account & Connection');
    await tester.enterText(_settingsTextField('Network ID'), 'mobile-network');
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
    // Wait for persistence and UI feedback (the dropdown re-enables) before
    // starting another preference edit.
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
    expect(find.text('通用').hitTestable(), findsWidgets);
    expect(find.text('语言').hitTestable(), findsOneWidget);
    expect(find.text('暗色模式').hitTestable(), findsOneWidget);
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
        await _openCategory(tester, 'Diagnostics & About');
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

    // The Account & Connection detail carries the credential state on the
    // compact desktop settings layout.
    await _openCategory(tester, 'Account & Connection');
    expect(find.text('Securely saved'), findsOneWidget);

    await tester.runAsync(
      () => stores.settingsStore.updateLanguageCode('zh-Hans'),
    );
    await tester.pump();

    expect(find.text('已安全保存'), findsOneWidget);
    expect(find.text('Securely saved'), findsNothing);

    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(authToken: ''),
      ),
    );
    await tester.pump();

    expect(find.text('未保存凭据'), findsOneWidget);
    expect(find.text('已安全保存'), findsNothing);
  });

  testWidgets('cached account identity remains visible without a token', (
    tester,
  ) async {
    final stores = (await tester.runAsync(() async {
      final s = await _makeStores(api: _FakeDiagnosticsApi(health: false));
      await s.settingsStore.updateSettings(
        s.settingsStore.settings.copyWith(
          accountEmail: 'cached@example.com',
          accountUsername: 'cached-user',
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
        ),
      ),
    );
    await tester.pumpAndSettle();
    await _openCategory(tester, 'Account & Connection');

    expect(find.text('cached-user'), findsOneWidget);
    expect(find.text('cached@example.com'), findsOneWidget);
    expect(
      find.text(
        'Showing the last account loaded successfully; it refreshes when connected.',
      ),
      findsOneWidget,
    );
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
    await _openCategory(tester, 'General');
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

    // Let the temporary save feedback finish before using the persistent
    // restart action; its dismiss button can overlap the action near the top.
    await tester.pump(const Duration(seconds: 4));
    await tester.pumpAndSettle();
    final restart = find.widgetWithText(TextButton, 'Restart and apply');
    await tester.ensureVisible(restart);
    await tester.pumpAndSettle();
    expect(restart.hitTestable(), findsOneWidget);
    // Applying the pending restart clears the notice.
    await tester.tap(restart);
    await tester.pump();
    await _waitFor(
      tester,
      () => find.text('P2WLAN restart required').evaluate().isEmpty,
    );
    expect(find.text('P2WLAN restart required'), findsNothing);
    expect(find.text('Restart and apply'), findsNothing);
  });

  for (final stopFails in [true, false]) {
    testWidgets(
      'Settings restart distinguishes ${stopFails ? 'stop' : 'start'} failure and preserves pending changes',
      (tester) async {
        final api = _FakeDiagnosticsApi(
          health: true,
          snapshot: await tester.runAsync(_loadFixtureSnapshot),
        );
        final controller = _RetryNetworkDaemonController(api)
          ..stopOk = !stopFails
          ..startOk = false;
        final stores = await _pumpSettings(
          tester,
          api: api,
          daemonController: controller,
        );
        await stores.statusStore.refresh();
        await _openCategory(tester, 'Advanced Network');
        await tester.enterText(_settingsTextField('MTU'), '1280');
        await tester.pump();
        await _tapSave(tester);
        await _waitFor(
          tester,
          () => find.text('Restart and apply').evaluate().isNotEmpty,
        );
        await _tapVisible(tester, find.text('Restart and apply'));
        final retry = stopFails
            ? 'Retry stopping and restarting'
            : 'Retry starting';
        await _waitFor(tester, () => find.text(retry).evaluate().isNotEmpty);
        expect(controller.stops, 1);
        expect(controller.starts, stopFails ? 0 : 1);
        expect(stores.statusStore.primaryConfigurationPending, isTrue);
        expect(
          find.text('The saved configuration is still pending confirmation.'),
          findsOneWidget,
        );
        await tester.pump(const Duration(seconds: 6));
        expect(find.text(retry), findsOneWidget);
        controller.stopOk = true;
        controller.startOk = true;
        await _tapVisible(tester, find.text(retry));
        await _waitFor(
          tester,
          () => !stores.statusStore.primaryConfigurationPending,
        );
        expect(controller.stops, stopFails ? 2 : 1);
        expect(controller.starts, stopFails ? 1 : 2);
        expect(find.text(retry), findsNothing);
        expect(stores.settingsStore.settings.mtu, 1280);
      },
    );
  }

  for (final scenario in ['leave', 'endpoint', 'replacement', 'disposed']) {
    final changeOwner = scenario != 'leave';
    testWidgets(
      'Settings restart ${scenario == 'endpoint'
          ? 'rejects a changed endpoint'
          : scenario == 'replacement'
          ? 'rejects a replacement owner with the same revision and endpoint'
          : scenario == 'disposed'
          ? 'rejects a disposed store'
          : 'finishes on its original owner'} after leaving',
      (tester) async {
        final api = _FakeDiagnosticsApi(
          health: true,
          snapshot: await tester.runAsync(_loadFixtureSnapshot),
        );
        final controller = _DeferredRestartDaemonController(api);
        final original = await _pumpSettings(
          tester,
          api: api,
          daemonController: controller,
        );
        await original.statusStore.refresh();
        final originalUrl = original.settingsStore.settings.diagnosticsUrl;
        await tester.runAsync(
          () => original.settingsStore.updateSettings(
            original.settingsStore.settings.copyWith(mtu: 1280),
          ),
        );
        await tester.pumpAndSettle();
        await _openCategory(tester, 'General');
        await _tapVisibleNoSettle(tester, find.text('Restart and apply'));
        expect(controller.stops, 1);
        expect(controller.starts, 0);
        final replacementApi = _FakeDiagnosticsApi(health: false);
        final replacementController = _RetryNetworkDaemonController(
          replacementApi,
        );
        final replacement = (await tester.runAsync(
          () => _makeStores(
            api: replacementApi,
            daemonController: replacementController,
          ),
        ))!;
        addTearDown(replacement.dispose);
        expect(
          replacement.statusStore.sessionRevision,
          original.statusStore.sessionRevision,
        );
        expect(replacement.settingsStore.settings.diagnosticsUrl, originalUrl);
        await tester.pumpWidget(
          _TestApp(
            child: SettingsPage(
              key: scenario == 'replacement'
                  ? null
                  : const ValueKey('replacement-settings'),
              settingsStore: replacement.settingsStore,
              statusStore: replacement.statusStore,
            ),
          ),
        );
        await tester.pumpAndSettle();
        if (scenario == 'endpoint') {
          await tester.runAsync(
            () => original.settingsStore.updateSettings(
              original.settingsStore.settings.copyWith(
                diagnosticsUrl: 'http://127.0.0.1:39279',
              ),
            ),
          );
        }
        if (scenario == 'disposed') original.statusStore.dispose();
        controller.pendingStop.complete(
          const DaemonCommandResult(ok: true, message: 'stopped'),
        );
        await _waitFor(tester, () => !original.statusStore.daemonBusy);
        await tester.pumpAndSettle();
        expect(controller.starts, changeOwner ? 0 : 1);
        expect(replacementController.starts, 0);
        if (scenario == 'replacement') {
          expect(
            find.byKey(const ValueKey('local-connection-restart-feedback')),
            findsNothing,
          );
          expect(
            tester
                .widget<SegmentedButton<String>>(
                  find.byKey(const ValueKey('settings-theme-select')),
                )
                .onSelectionChanged,
            isNotNull,
          );
        }
        if (!changeOwner) {
          expect(controller.startedSettings.single.diagnosticsUrl, originalUrl);
          expect(original.statusStore.primaryConfigurationPending, isFalse);
        }
        expect(tester.takeException(), isNull);
      },
    );
  }
}
