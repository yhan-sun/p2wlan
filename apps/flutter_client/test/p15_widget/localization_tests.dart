part of '../p15_widget_test.dart';

void _registerLocalizationTests() {
  final pages = <String, Widget Function(_Stores)>{
    'Login': (s) => LoginPage(
      settingsStore: s.settingsStore,
      statusStore: s.statusStore,
      capabilities: PlatformCapabilities.fromPlatform('macos'),
      controlApi: _FakeControlApi(),
      onAuthenticated: () {},
    ),
    'Settings': (s) => SettingsPage(
      settingsStore: s.settingsStore,
      statusStore: s.statusStore,
      onLogout: () {},
      capabilities: PlatformCapabilities.fromPlatform('macos'),
    ),
    'Diagnostics': (s) => DiagnosticsPage(
      statusStore: s.statusStore,
      capabilities: PlatformCapabilities.fromPlatform('macos'),
      permissionCheck: _noopPermissionCheck,
      logPreviewLoader: _noopLogPreviewLoader,
    ),
    'Nodes': (s) => NodesPage(
      settingsStore: s.settingsStore,
      statusStore: s.statusStore,
      controlApi: _FakeControlApi(),
    ),
  };

  for (final entry in pages.entries) {
    testWidgets('${entry.key} English UI has no Chinese text', (tester) async {
      final stores = await _smokeStores(tester);
      addTearDown(stores.dispose);
      await tester.pumpWidget(_localeHost(tester, 'en', entry.value(stores)));
      await tester.pumpAndSettle();
      _expectNoCjk(tester, page: entry.key);
      expect(tester.takeException(), isNull);
    });
  }

  testWidgets('Login Chinese UI shows localized copy, not English', (
    tester,
  ) async {
    final stores = await _smokeStores(tester);
    addTearDown(stores.dispose);
    await tester.pumpWidget(
      _localeHost(
        tester,
        'zh-Hans',
        LoginPage(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          controlApi: _FakeControlApi(),
          onAuthenticated: () {},
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('登录'), findsOneWidget);
    expect(find.textContaining('创建账号'), findsOneWidget);
    expect(find.text('密码'), findsOneWidget);
    expect(find.text('Sign in'), findsNothing);
    expect(find.text('Create account'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('Diagnostics Chinese UI shows localized copy, not English', (
    tester,
  ) async {
    final stores = await _smokeStores(tester);
    addTearDown(stores.dispose);
    await tester.pumpWidget(
      _localeHost(
        tester,
        'zh-Hans',
        DiagnosticsPage(
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
          permissionCheck: _noopPermissionCheck,
          logPreviewLoader: _noopLogPreviewLoader,
        ),
      ),
    );
    await tester.pumpAndSettle();
    expect(find.text('状态检查'), findsOneWidget);
    expect(find.textContaining('P2WLAN'), findsWidgets);
    expect(find.text('No action needed'), findsNothing);
    expect(tester.takeException(), isNull);
  });

  // Long-copy responsive: Settings / Diagnostics / Login in both locales at
  // the narrowest supported width.
  final longCopyPages =
      <String, Widget Function(WidgetTester, String, _Stores)>{
        'Login': (tester, code, s) => _localeHost(
          tester,
          code,
          LoginPage(
            settingsStore: s.settingsStore,
            statusStore: s.statusStore,
            capabilities: PlatformCapabilities.fromPlatform('macos'),
            controlApi: _FakeControlApi(),
            onAuthenticated: () {},
          ),
        ),
        'Settings': (tester, code, s) => _localeHost(
          tester,
          code,
          SettingsPage(
            settingsStore: s.settingsStore,
            statusStore: s.statusStore,
            onLogout: () {},
            capabilities: PlatformCapabilities.fromPlatform('macos'),
          ),
        ),
        'Diagnostics': (tester, code, s) => _localeHost(
          tester,
          code,
          DiagnosticsPage(
            statusStore: s.statusStore,
            capabilities: PlatformCapabilities.fromPlatform('macos'),
            permissionCheck: _noopPermissionCheck,
            logPreviewLoader: _noopLogPreviewLoader,
          ),
        ),
      };
  for (final entry in longCopyPages.entries) {
    for (final code in ['en', 'zh-Hans']) {
      testWidgets('${entry.key} 390x844 fits $code', (tester) async {
        await tester.binding.setSurfaceSize(const Size(390, 844));
        addTearDown(() => tester.binding.setSurfaceSize(null));
        final stores = await _smokeStores(tester);
        addTearDown(stores.dispose);
        await tester.pumpWidget(entry.value(tester, code, stores));
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      });
    }
  }
}

Widget _localeHost(WidgetTester tester, String code, Widget child) {
  return MaterialApp(
    theme: AppTheme.lightTheme,
    home: AppStringsScope(
      strings: AppStrings.fromCode(code),
      child: ScaffoldMessenger(child: Scaffold(body: child)),
    ),
  );
}

final _cjk = RegExp(r'[\u4e00-\u9fff\u3000-\u303f\uff00-\uffef]');

void _expectNoCjk(WidgetTester tester, {required String page}) {
  final texts = <String>[
    ...tester.widgetList<Text>(find.byType(Text)).map((t) => t.data ?? ''),
    ...tester
        .widgetList<EditableText>(find.byType(EditableText))
        .map((t) => t.controller.text),
  ];
  for (final text in texts) {
    if (_cjk.hasMatch(text)) {
      fail('$page English UI leaked Chinese text: "$text"');
    }
  }
}
