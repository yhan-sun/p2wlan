part of '../p15_widget_test.dart';

void _registerSettingsRedesignTests() {
  for (final failWrite in [false, true]) {
    testWidgets(
      'Settings keeps save feedback and leave protection until persistence ${failWrite ? 'fails' : 'completes'}',
      (tester) async {
        final repository = _PausedSettingsTokenRepository();
        addTearDown(repository.release);
        final dirtyStates = <bool>[];
        final stores = await _pumpSettings(
          tester,
          api: _FakeDiagnosticsApi(health: false),
          tokenRepository: repository,
          onDirtyChanged: dirtyStates.add,
          physicalSize: const Size(800, 800),
        );
        await _openCategory(tester, 'General');
        final originalName = stores.settingsStore.settings.deviceName;
        final device = _settingsTextField('Device name');
        await tester.enterText(device, 'Demo updated device');
        await tester.pump();
        repository.pauseNextWrite();
        await _tapSave(tester);
        await _waitFor(tester, () => repository.waiting);
        expect(stores.settingsStore.settings.deviceName, originalName);
        final save = find.byKey(const Key('settings-save-button'));
        expect(save, findsOneWidget);
        expect(tester.widget<FilledButton>(save).onPressed, isNull);
        expect(dirtyStates.last, isTrue);
        expect(tester.testTextInput.isVisible, isFalse);
        repository.release(fail: failWrite);
        if (failWrite) {
          await _waitFor(
            tester,
            () => find
                .text(AppStrings.fromCode('en').settingsSaveFailed)
                .evaluate()
                .isNotEmpty,
          );
          expect(stores.settingsStore.settings.deviceName, originalName);
          expect(
            tester.widget<TextField>(device).controller!.text,
            'Demo updated device',
          );
          expect(dirtyStates.last, isTrue);
          expect(tester.widget<FilledButton>(save).onPressed, isNotNull);
        } else {
          await _waitFor(tester, () => save.evaluate().isEmpty);
          expect(dirtyStates.last, isFalse);
          expect(
            stores.settingsStore.settings.deviceName,
            'Demo updated device',
          );
        }
        expect(tester.takeException(), isNull);
      },
    );
  }

  testWidgets(
    'credential recovery failure keeps settings draft and asks for sign in',
    (tester) async {
      final repository = _PausedSettingsTokenRepository();
      addTearDown(repository.release);
      final dirtyStates = <bool>[];
      final stores = await _pumpSettings(
        tester,
        api: _FakeDiagnosticsApi(health: false),
        tokenRepository: repository,
        onDirtyChanged: dirtyStates.add,
      );
      await _openCategory(tester, 'General');
      final original = stores.settingsStore.settings.deviceName;
      await tester.enterText(
        _settingsTextField('Device name'),
        'Unsaved device',
      );
      await tester.pump();
      repository.pauseNextWrite();
      await _tapSave(tester);
      await _waitFor(tester, () => repository.waiting);
      repository.release(
        error: SettingsCredentialRestoreException(
          StateError('private file error'),
          StateError('private restore error'),
        ),
      );
      const message =
          'Settings could not be saved and your sign-in credential could not be restored. Sign in again before reconnecting.';
      await _waitFor(tester, () => find.text(message).evaluate().isNotEmpty);
      expect(stores.settingsStore.settings.deviceName, original);
      expect(
        tester
            .widget<TextField>(_settingsTextField('Device name'))
            .controller!
            .text,
        'Unsaved device',
      );
      expect(dirtyStates.last, isTrue);
      expect(
        tester
            .widget<FilledButton>(find.byKey(const Key('settings-save-button')))
            .onPressed,
        isNotNull,
      );
      expect(find.textContaining('private restore error'), findsNothing);
    },
  );

  testWidgets('username draft survives categories and uses the leave guard', (
    tester,
  ) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
    addTearDown(() => debugDefaultTargetPlatformOverride = null);
    tester.view.physicalSize = const Size(1280, 900);
    tester.view.devicePixelRatio = 1;
    addTearDown(tester.view.resetPhysicalSize);
    addTearDown(tester.view.resetDevicePixelRatio);
    final stores = (await tester.runAsync(
      () => _makeStores(
        api: _FakeDiagnosticsApi(health: false),
        authToken: 'demo-token',
      ),
    ))!;
    addTearDown(stores.dispose);
    await tester.runAsync(
      () => stores.settingsStore.updateSettings(
        stores.settingsStore.settings.copyWith(accountUsername: 'Original'),
      ),
    );
    await tester.pumpWidget(
      _TestApp(
        child: P2WlanShell(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
        ),
      ),
    );
    await tester.pumpAndSettle();
    Finder section(String label) => find.descendant(
      of: find.byType(DesktopSidebar),
      matching: find.text(label),
    );
    await tester.tap(section('Settings'));
    await tester.pumpAndSettle();
    await _openCategory(tester, 'Account & Connection');
    await tester.enterText(_settingsTextField('Username'), 'Unsaved username');
    await tester.pump();
    // The profile has its own save action. Connection Save must not imply
    // that it will submit the independent username draft.
    expect(find.byKey(const Key('settings-save-button')), findsNothing);
    await _openCategory(tester, 'General');
    await _openCategory(tester, 'Account & Connection');
    expect(
      tester.widget<TextField>(_settingsTextField('Username')).controller!.text,
      'Unsaved username',
    );
    await tester.tap(section('Home'));
    await tester.pumpAndSettle();
    expect(find.text('Discard unsaved changes?'), findsOneWidget);
    await tester.tap(find.text('Continue editing'));
    await tester.pumpAndSettle();
    expect(
      tester.widget<TextField>(_settingsTextField('Username')).controller!.text,
      'Unsaved username',
    );
    await tester.tap(section('Home'));
    await tester.pumpAndSettle();
    await tester.tap(find.text('Discard changes'));
    await tester.pumpAndSettle();
    await tester.tap(section('Settings'));
    await tester.pumpAndSettle();
    await _openCategory(tester, 'Account & Connection');
    expect(
      tester.widget<TextField>(_settingsTextField('Username')).controller!.text,
      'Original',
    );
    expect(tester.takeException(), isNull);
    debugDefaultTargetPlatformOverride = null;
  });

  for (final spec in [
    (const Size(800, 800), false, 1.0, 'settings-shell-800'),
    (const Size(390, 844), true, 1.5, 'settings-shell-mobile-dark-large'),
  ]) {
    testWidgets('Settings layout shell ${spec.$4}', (tester) async {
      debugDefaultTargetPlatformOverride = spec.$1.width < 600
          ? TargetPlatform.android
          : TargetPlatform.macOS;
      addTearDown(() => debugDefaultTargetPlatformOverride = null);
      final stores = (await tester.runAsync(
        () => _makeStores(
          api: _FakeDiagnosticsApi(health: false),
          deviceName: 'Demo workstation',
        ),
      ))!;
      addTearDown(stores.dispose);
      await tester.runAsync(
        () => stores.settingsStore.updateLanguageCode('zh-Hans'),
      );
      tester.view.physicalSize = spec.$1;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final theme = spec.$2 ? AppTheme.darkTheme : AppTheme.lightTheme;
      await tester.pumpWidget(
        MaterialApp(
          theme: theme,
          builder: (context, child) => MediaQuery(
            data: MediaQuery.of(context)
                .copyWith(textScaler: TextScaler.linear(spec.$3)),
            child: child!,
          ),
          home: AppStringsScope(
            strings: AppStrings.fromCode('zh-Hans'),
            child: P2WlanShell(
              settingsStore: stores.settingsStore,
              statusStore: stores.statusStore,
              capabilities: PlatformCapabilities.fromPlatform(
                spec.$1.width < 600 ? 'android' : 'macos',
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      final tooltip = find.byTooltip('设置');
      await tester.tap(
        tooltip.evaluate().isNotEmpty ? tooltip : find.text('设置'),
      );
      await tester.pumpAndSettle();
      debugDefaultTargetPlatformOverride = null;
      expect(find.byType(SettingsPage), findsOneWidget);
      final general = find.byKey(
        const ValueKey('settings-category-card-general'),
      );
      final account = find.byKey(
        const ValueKey('settings-category-card-accountNetwork'),
      );
      if (spec.$1.width == 800) {
        expect(tester.getTopLeft(general).dy, tester.getTopLeft(account).dy);
        expect(
          tester.getTopLeft(account).dx,
          greaterThan(tester.getTopLeft(general).dx),
        );
      } else {
        expect(
          tester.getTopLeft(account).dy,
          greaterThan(tester.getTopLeft(general).dy),
        );
      }
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets(
    'Settings shell keeps the selected section and refreshes account after sign in',
    (tester) async {
      var signIns = 0;
      final stores = await _pumpSettingsShell(
        tester,
        const Size(1280, 900),
        onReauthenticate: () => signIns++,
      );
      await _openCategory(tester, 'Account & Connection');
      await tester.tap(find.byKey(const ValueKey('settings-reauthenticate')));
      expect(signIns, 1);
      await tester.runAsync(
        () => stores.settingsStore.updateSettings(
          stores.settingsStore.settings.copyWith(
            controlServer: 'https://updated.example.com',
            authToken: 'updated-session',
            accountEmail: 'updated@example.com',
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(find.byType(SettingsPage), findsOneWidget);
      await _openCategory(tester, 'Account & Connection');
      expect(
        tester
            .widget<TextField>(_settingsTextField('Control server'))
            .controller!
            .text,
        'https://updated.example.com',
      );
      expect(find.byKey(const Key('settings-save-button')), findsNothing);
      expect(find.textContaining('updated-session'), findsNothing);
      expect(tester.takeException(), isNull);
    },
  );

  testWidgets(
    'Settings sign in respects dirty guard and cancelled sign in keeps drafts',
    (tester) async {
      var signIns = 0;
      await _pumpSettingsShell(
        tester,
        const Size(1280, 900),
        onReauthenticate: () => signIns++,
      );
      await _openCategory(tester, 'Account & Connection');
      await tester.enterText(
        _settingsTextField('Control server'),
        'https://draft.example.com',
      );
      await tester.pump();
      await tester.tap(find.byKey(const ValueKey('settings-reauthenticate')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Continue editing'));
      await tester.pumpAndSettle();
      expect(signIns, 0);
      await tester.tap(find.byKey(const ValueKey('settings-reauthenticate')));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Discard changes'));
      await tester.pumpAndSettle();
      expect(signIns, 1);
      // Returning without a session change represents cancelling the login page.
      expect(
        tester
            .widget<TextField>(_settingsTextField('Control server'))
            .controller!
            .text,
        'https://draft.example.com',
      );
      expect(find.byKey(const Key('settings-save-button')), findsOneWidget);
    },
  );

  testWidgets('Settings rejects invalid MTU and keeps the saved value', (
    tester,
  ) async {
    final stores = await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: false),
    );
    final savedMtu = stores.settingsStore.settings.mtu;
    await _openCategory(tester, 'Advanced Network');
    for (final draft in ['abc', '', '575', '65536', '1420.5']) {
      await tester.enterText(_settingsTextField('MTU'), draft);
      await tester.pump();
      await _tapSave(tester);
      await tester.pumpAndSettle();
      final field = tester.widget<TextField>(_settingsTextField('MTU'));
      expect(
        field.decoration!.errorText,
        'Enter a whole number from 576 to 65535.',
      );
      expect(field.focusNode!.hasFocus, isTrue);
      expect(field.controller!.text, draft);
      expect(stores.settingsStore.settings.mtu, savedMtu);
      expect(find.byKey(const Key('settings-save-button')), findsOneWidget);
    }
    await tester.tap(find.byKey(const ValueKey('settings-mtu-default')));
    await tester.pumpAndSettle();
    expect(
      tester.widget<TextField>(_settingsTextField('MTU')).decoration!.errorText,
      isNull,
    );
    expect(
      tester.widget<TextField>(_settingsTextField('MTU')).controller!.text,
      defaultMtu.toString(),
    );
  });

  testWidgets('Settings offers direct sign in again in the account category', (
    tester,
  ) async {
    var signIns = 0;
    await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: false),
      onReauthenticate: () => signIns++,
    );
    await _openCategory(tester, 'Account & Connection');
    await tester.tap(find.byKey(const ValueKey('settings-reauthenticate')));
    expect(signIns, 1);
  });

  testWidgets(
    'Settings redesign: undo is scoped and keeps immediate preferences',
    (tester) async {
      final stores = await _pumpSettings(
        tester,
        api: _FakeDiagnosticsApi(health: false),
      );
      final originalName = stores.settingsStore.settings.deviceName;
      await _openCategory(tester, 'Advanced Network');
      await tester.enterText(_settingsTextField('MTU'), '1301');
      await tester.pump();
      await _openCategory(tester, 'General');
      expect(
        find.byKey(const ValueKey('settings-close-behavior-select')),
        findsOneWidget,
      );
      await tester.enterText(
        _settingsTextField('Device name'),
        'changed-device',
      );
      await tester.pump();
      await _openAppSelect(tester, const ValueKey('settings-theme-select'));
      await tester.tap(find.text('Dark'));
      await tester.pump();
      await _waitForSaveComplete(
        tester,
        const ValueKey('settings-theme-select'),
      );
      expect(find.text('Theme saved'), findsOneWidget);
      await tester.tap(find.byKey(const Key('settings-undo-button')));
      await tester.pumpAndSettle();
      expect(
        tester
            .widget<TextField>(_settingsTextField('Device name'))
            .controller!
            .text,
        originalName,
      );
      expect(stores.settingsStore.settings.themeMode, 'dark');
      expect(find.byKey(const Key('settings-save-button')), findsNothing);
      await _openCategory(tester, 'Advanced Network');
      expect(
        tester.widget<TextField>(_settingsTextField('MTU')).controller!.text,
        '1301',
      );
      expect(find.byKey(const Key('settings-save-button')), findsOneWidget);
    },
  );

  testWidgets('Settings redesign: restart impact precedes save', (
    tester,
  ) async {
    final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
    final stores = await _pumpSettings(
      tester,
      api: _FakeDiagnosticsApi(health: true, snapshot: snapshot),
    );
    await stores.statusStore.refresh();
    await _openCategory(tester, 'Advanced Network');
    await tester.enterText(_settingsTextField('MTU'), '1302');
    await tester.pumpAndSettle();
    expect(
      find.text(AppStrings.fromCode('en').settingsReconnectImpact),
      findsOneWidget,
    );
    expect(stores.settingsStore.settings.mtu, isNot(1302));
    await tester.tap(find.byKey(const Key('settings-undo-button')));
    await tester.pumpAndSettle();
    expect(
      find.text(AppStrings.fromCode('en').settingsReconnectImpact),
      findsNothing,
    );
  });

  testWidgets('Settings redesign: build details collapse and copy as a whole', (
    tester,
  ) async {
    await _pumpSettings(tester, api: _FakeDiagnosticsApi(health: false));
    String? copied;
    tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
      SystemChannels.platform,
      (call) async {
        if (call.method == 'Clipboard.setData') {
          copied = (call.arguments as Map)['text'] as String;
        }
        return null;
      },
    );
    addTearDown(
      () => tester.binding.defaultBinaryMessenger.setMockMethodCallHandler(
        SystemChannels.platform,
        null,
      ),
    );
    await _openCategory(tester, 'Diagnostics & About');
    final expansion = find.byKey(
      const PageStorageKey('settings-build-details'),
    );
    await tester.ensureVisible(expansion);
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('settings-copy-build-details')), findsNothing);
    await tester.tap(find.text('Build details'));
    await tester.pumpAndSettle();
    final copy = find.byKey(const Key('settings-copy-build-details'));
    await tester.ensureVisible(copy);
    await tester.pumpAndSettle();
    await tester.tap(copy);
    await tester.pumpAndSettle();
    expect(copied, contains(AppStrings.fromCode('en').buildCommitLabel));
    expect(copied, contains(AppStrings.fromCode('en').buildIdLabel));
  });

  for (final variant in [
    (const Size(1280, 900), false, 1.0, 'desktop-light'),
    (const Size(900, 800), true, 1.0, 'desktop-dark'),
    (const Size(790, 900), false, 1.0, 'desktop-root'),
    (const Size(390, 844), false, 1.0, 'mobile'),
    (const Size(320, 740), true, 1.5, 'narrow-large-text'),
  ]) {
    testWidgets('Settings redesign: layout ${variant.$4}', (tester) async {
      final stores = (await tester.runAsync(
        () => _makeStores(api: _FakeDiagnosticsApi(health: false)),
      ))!;
      addTearDown(stores.dispose);
      await tester.runAsync(
        () => stores.settingsStore.updateSettings(
          stores.settingsStore.settings.copyWith(
            languageCode: 'zh-Hans',
            deviceName: '演示设备',
          ),
        ),
      );
      tester.view.physicalSize = variant.$1;
      tester.view.devicePixelRatio = 1;
      addTearDown(tester.view.resetPhysicalSize);
      addTearDown(tester.view.resetDevicePixelRatio);
      final theme = variant.$2 ? AppTheme.darkTheme : AppTheme.lightTheme;
      await tester.pumpWidget(
        MaterialApp(
          theme: theme,
          builder: (context, child) => MediaQuery(
            data: MediaQuery.of(context)
                .copyWith(textScaler: TextScaler.linear(variant.$3)),
            child: child!,
          ),
          home: Scaffold(
            backgroundColor: theme.colorScheme.surfaceContainerLow,
            body: SettingsPage(
              settingsStore: stores.settingsStore,
              statusStore: stores.statusStore,
              capabilities: PlatformCapabilities.fromPlatform(
                variant.$1.width < 500 ? 'android' : 'macos',
              ),
            ),
          ),
        ),
      );
      await tester.pumpAndSettle();
      expect(tester.takeException(), isNull);
      if (variant.$4 == 'desktop-root') {
        final general = find.byKey(
          const ValueKey('settings-category-card-general'),
        );
        final account = find.byKey(
          const ValueKey('settings-category-card-accountNetwork'),
        );
        expect(tester.getTopLeft(general).dy, tester.getTopLeft(account).dy);
        expect(
          tester.getTopLeft(account).dx,
          greaterThan(tester.getTopLeft(general).dx),
        );
        expect(find.byType(TextField), findsNothing);
        return;
      }
      for (final category in ['通用', '账户与连接', '高级网络', '诊断与关于']) {
        // Mobile routes use the native back control.
        final back = find.byKey(const Key('settings-mobile-category-back'));
        if (back.evaluate().isNotEmpty) {
          await tester.tap(back);
          await tester.pumpAndSettle();
        }
        await _openCategory(tester, category);
        expect(tester.takeException(), isNull);
        // Exercise long forms all the way down, including scaled text.
        final list = find.byType(ListView).last;
        await tester.drag(list, const Offset(0, -1400));
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
        expect(find.byType(ListView), findsWidgets);
      }
    });
  }

  for (final size in [const Size(320, 740), const Size(390, 844)]) {
    testWidgets(
      'Settings large English form keeps help and save actions usable at ${size.width.toInt()}',
      (tester) async {
        final stores = (await tester.runAsync(
          () => _makeStores(
            api: _FakeDiagnosticsApi(health: false),
            deviceName: 'Demo workstation',
          ),
        ))!;
        addTearDown(stores.dispose);
        tester.view.physicalSize = size;
        tester.view.devicePixelRatio = 1;
        addTearDown(tester.view.resetPhysicalSize);
        addTearDown(tester.view.resetDevicePixelRatio);
        await tester.pumpWidget(
          MaterialApp(
            theme: AppTheme.darkTheme,
            builder: (context, child) => MediaQuery(
              data: MediaQuery.of(context)
                  .copyWith(textScaler: const TextScaler.linear(2)),
              child: child!,
            ),
            home: Scaffold(
              body: SettingsPage(
                settingsStore: stores.settingsStore,
                statusStore: stores.statusStore,
                capabilities: PlatformCapabilities.fromPlatform('android'),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();
        await _openCategory(tester, 'General');
        final helper = find.text(AppStrings.fromCode('en').deviceNameHelper);
        await tester.ensureVisible(helper);
        await tester.pumpAndSettle();
        final richHelper = tester.widget<RichText>(
          find.descendant(of: helper, matching: find.byType(RichText)),
        );
        expect(richHelper.maxLines, isNull);
        final device = _settingsTextField('Device name');
        await tester.ensureVisible(device);
        await tester.enterText(device, 'Updated demo workstation');
        await tester.pumpAndSettle();
        final save = find.byKey(const Key('settings-save-button'));
        final undo = find.byKey(const Key('settings-undo-button'));
        expect(save.hitTestable(), findsOneWidget);
        expect(undo.hitTestable(), findsOneWidget);
        expect(tester.getSize(save).width, greaterThan(size.width - 90));
        expect(
          tester.getTopLeft(undo).dy,
          greaterThan(tester.getBottomLeft(save).dy),
        );
        await tester.tap(undo);
        await tester.pumpAndSettle();
        expect(save, findsNothing);
        expect(
          tester.widget<TextField>(device).controller!.text,
          'Demo workstation',
        );
        expect(tester.takeException(), isNull);
      },
    );
  }
}

class _PausedSettingsTokenRepository implements SecureTokenRepository {
  String? _token;
  Completer<void>? _write;
  bool waiting = false;

  void pauseNextWrite() => _write = Completer<void>();
  void release({bool fail = false, Object? error}) {
    final write = _write;
    if (write == null || write.isCompleted) return;
    if (error != null) {
      write.completeError(error);
    } else if (fail) {
      write.completeError(
        const SecureTokenStorageException('test storage unavailable'),
      );
    } else {
      write.complete();
    }
  }

  @override
  Future<String?> read() async => _token;
  @override
  Future<void> clear() async => _token = null;
  @override
  Future<void> write(String token) async {
    final write = _write;
    if (write != null) {
      waiting = true;
      try {
        await write.future;
      } finally {
        _write = null;
        waiting = false;
      }
    }
    _token = token;
  }
}
