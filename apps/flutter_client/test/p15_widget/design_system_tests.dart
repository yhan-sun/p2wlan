part of '../p15_widget_test.dart';

void _registerDesignSystemTests() {
  for (final dark in [false, true]) {
    testWidgets(
      'selected ChoiceChip uses selectedSurface in ${dark ? 'dark' : 'light'}',
      (tester) async {
        await tester.pumpWidget(
          _DesignSystemHost(
            dark: dark,
            child: const ChoiceChip(label: Text('filter'), selected: true),
          ),
        );

        final c = dark ? P2WlanColors.dark : P2WlanColors.light;
        // ChoiceChip builds a RawChip whose resolved selected background comes
        // from the chip theme's secondarySelectedColor; assert the real
        // rendered contract (chips paint via their own decoration, so RawChip
        // is the stable surface to inspect).
        final raw = tester.widget<RawChip>(find.byType(RawChip));
        expect(raw.selected, isTrue);
        expect(raw.selectedColor, c.selectedSurface);
        // Selected label/checkmark stay on the brand accent family.
        expect(
          AppTheme.lightTheme.chipTheme.secondarySelectedColor,
          P2WlanColors.light.selectedSurface,
        );
        expect(
          AppTheme.darkTheme.chipTheme.secondarySelectedColor,
          P2WlanColors.dark.selectedSurface,
        );
        expect(tester.takeException(), isNull);
      },
    );
  }

  for (final dark in [false, true]) {
    testWidgets(
      'P2WlanColors.of falls back by brightness ${dark ? 'dark' : 'light'}',
      (tester) async {
        P2WlanColors? resolved;
        await tester.pumpWidget(
          Theme(
            data: dark ? ThemeData.dark() : ThemeData.light(),
            child: Builder(
              builder: (context) {
                resolved = P2WlanColors.of(context);
                return const SizedBox.shrink();
              },
            ),
          ),
        );
        expect(resolved, dark ? P2WlanColors.dark : P2WlanColors.light);
        expect(tester.takeException(), isNull);
      },
    );
  }

  for (final dark in [false, true]) {
    testWidgets(
      'StatusBadge tones resolve in ${dark ? 'dark' : 'light'} theme',
      (tester) async {
        await tester.pumpWidget(
          _DesignSystemHost(
            dark: dark,
            child: const Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                StatusBadge(label: 'good', tone: StatusTone.good),
                StatusBadge(label: 'warn', tone: StatusTone.warn),
                StatusBadge(label: 'bad', tone: StatusTone.bad),
                StatusBadge(label: 'neutral', tone: StatusTone.neutral),
              ],
            ),
          ),
        );

        final c = dark ? P2WlanColors.dark : P2WlanColors.light;
        final containers = tester
            .widgetList<Container>(find.byType(Container))
            .where(
              (w) =>
                  w.decoration is BoxDecoration &&
                  (w.decoration as BoxDecoration).color != null,
            )
            .map((w) => (w.decoration as BoxDecoration).color)
            .toList();
        expect(containers, contains(c.successSurface));
        expect(containers, contains(c.warningSurface));
        expect(containers, contains(c.dangerSurface));
        expect(containers, contains(c.neutralSurface));
        // Relay is a normal path: it never maps onto the warning semantic.
        expect(c.relay, isNot(equals(c.warningText)));
        expect(tester.takeException(), isNull);
      },
    );
  }

  for (final (name, builder) in [
    ('Dashboard', _pumpDashboardSmoke),
    ('Nodes', _pumpNodesSmoke),
    ('Settings', _pumpSettingsSmoke),
    ('Login', _pumpLoginSmoke),
    ('Diagnostics', _pumpDiagnosticsSmoke),
  ]) {
    for (final dark in [false, true]) {
      testWidgets('$name renders in ${dark ? 'dark' : 'light'} theme', (
        tester,
      ) async {
        await builder(tester, dark: dark);
        expect(tester.takeException(), isNull);
      });
    }
  }

  for (final size in const [Size(390, 844), Size(700, 1000), Size(1280, 900)]) {
    for (final dark in [false, true]) {
      testWidgets('shell smoke ${size.width.toInt()}x${size.height.toInt()} '
          '${dark ? 'dark' : 'light'}', (tester) async {
        await tester.binding.setSurfaceSize(size);
        addTearDown(() => tester.binding.setSurfaceSize(null));
        final stores = await _smokeStores(tester);
        addTearDown(stores.dispose);
        await tester.pumpWidget(
          _DesignSystemHost(
            dark: dark,
            child: P2WlanShell(
              settingsStore: stores.settingsStore,
              statusStore: stores.statusStore,
              capabilities: PlatformCapabilities.fromPlatform('macos'),
            ),
          ),
        );
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);
      });
    }
  }

  testWidgets('expanded dark shell renders sidebar, footer, and selection', (
    tester,
  ) async {
    await tester.binding.setSurfaceSize(const Size(1280, 900));
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final stores = await _smokeStores(tester);
    addTearDown(stores.dispose);
    await tester.pumpWidget(
      _DesignSystemHost(
        dark: true,
        child: P2WlanShell(
          settingsStore: stores.settingsStore,
          statusStore: stores.statusStore,
          capabilities: PlatformCapabilities.fromPlatform('macos'),
        ),
      ),
    );
    await tester.pumpAndSettle();

    // Sidebar with brand, primary sections, and the status footer.
    expect(find.byType(DesktopSidebar), findsOneWidget);
    expect(find.text('P2WLAN'), findsWidgets);
    expect(find.text('Home'), findsOneWidget);
    // Sidebar item and the Home section title share the Devices label.
    expect(find.text('Devices'), findsWidgets);
    expect(find.text('Troubleshooting'), findsOneWidget);
    expect(find.text('Settings'), findsOneWidget);
    // Footer: the smoke store reports a healthy snapshot with peers.
    expect(find.text('Network OK'), findsOneWidget);
    expect(tester.takeException(), isNull);
  });
}

Future<void> _pumpDashboardSmoke(
  WidgetTester tester, {
  required bool dark,
}) async {
  final stores = await _smokeStores(tester);
  addTearDown(stores.dispose);
  await tester.pumpWidget(
    _DesignSystemHost(
      dark: dark,
      child: DashboardPage(
        settingsStore: stores.settingsStore,
        statusStore: stores.statusStore,
        capabilities: PlatformCapabilities.fromPlatform('macos'),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> _pumpNodesSmoke(WidgetTester tester, {required bool dark}) async {
  final stores = await _smokeStores(tester);
  addTearDown(stores.dispose);
  await tester.pumpWidget(
    _DesignSystemHost(
      dark: dark,
      child: NodesPage(
        settingsStore: stores.settingsStore,
        statusStore: stores.statusStore,
        controlApi: _FakeControlApi(),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> _pumpSettingsSmoke(
  WidgetTester tester, {
  required bool dark,
}) async {
  final stores = await _smokeStores(tester);
  addTearDown(stores.dispose);
  await tester.pumpWidget(
    _DesignSystemHost(
      dark: dark,
      child: SettingsPage(
        settingsStore: stores.settingsStore,
        statusStore: stores.statusStore,
        onLogout: () {},
        capabilities: PlatformCapabilities.fromPlatform('macos'),
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> _pumpLoginSmoke(WidgetTester tester, {required bool dark}) async {
  final stores = await _smokeStores(tester);
  addTearDown(stores.dispose);
  await tester.pumpWidget(
    _DesignSystemHost(
      dark: dark,
      child: LoginPage(
        settingsStore: stores.settingsStore,
        statusStore: stores.statusStore,
        capabilities: PlatformCapabilities.fromPlatform('macos'),
        controlApi: _FakeControlApi(),
        onAuthenticated: () {},
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<void> _pumpDiagnosticsSmoke(
  WidgetTester tester, {
  required bool dark,
}) async {
  final stores = await _smokeStores(tester);
  addTearDown(stores.dispose);
  await tester.pumpWidget(
    _DesignSystemHost(
      dark: dark,
      child: DiagnosticsPage(
        statusStore: stores.statusStore,
        capabilities: PlatformCapabilities.fromPlatform('macos'),
        permissionCheck: _noopPermissionCheck,
        logPreviewLoader: _noopLogPreviewLoader,
      ),
    ),
  );
  await tester.pumpAndSettle();
}

Future<_Stores> _smokeStores(WidgetTester tester) async {
  final snapshot = (await tester.runAsync(_loadFixtureSnapshot))!;
  final stores = (await tester.runAsync(
    () =>
        _makeStores(api: _FakeDiagnosticsApi(health: true, snapshot: snapshot)),
  ))!;
  await stores.statusStore.refresh();
  return stores;
}

/// Renders [child] under the real P2WLAN light/dark themes (the page-level
/// tests elsewhere use the default Material theme, so they cannot catch
/// light/dark theme regressions).
class _DesignSystemHost extends StatelessWidget {
  const _DesignSystemHost({required this.dark, required this.child});

  final bool dark;
  final Widget child;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      theme: AppTheme.lightTheme,
      darkTheme: AppTheme.darkTheme,
      themeMode: dark ? ThemeMode.dark : ThemeMode.light,
      home: AppStringsScope(
        strings: AppStrings.fromCode(AppLanguage.english.code),
        child: ScaffoldMessenger(child: Scaffold(body: child)),
      ),
    );
  }
}
