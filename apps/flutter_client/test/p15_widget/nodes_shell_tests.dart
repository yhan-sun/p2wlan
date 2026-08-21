part of '../p15_widget_test.dart';

/// Full-shell Devices responsive-boundary tests.
///
/// These run through the real [P2WlanShell] (sidebar + page scaffold), not a
/// standalone [NodesPage], so the interaction is measured through the actual
/// shell chrome at each responsive boundary. All widths use the same compact
/// list-first interaction: tap a device to open its details.
void _registerNodesShellTests() {
  Future<void> pumpShell(WidgetTester tester, Size size) async {
    await tester.binding.setSurfaceSize(size);
    addTearDown(() => tester.binding.setSurfaceSize(null));
    final stores = await _smokeStores(tester);
    addTearDown(stores.dispose);
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
  }

  Future<void> goToDevices(WidgetTester tester) async {
    final sidebarItem = find.descendant(
      of: find.byType(DesktopSidebar),
      matching: find.text('Devices'),
    );
    final railItem = find.descendant(
      of: find.byType(AppNavRail),
      matching: find.text('Devices'),
    );
    final bottomItem = find.descendant(
      of: find.byType(NavigationBar),
      matching: find.text('Devices'),
    );
    final target = sidebarItem.evaluate().isNotEmpty
        ? sidebarItem
        : railItem.evaluate().isNotEmpty
        ? railItem
        : bottomItem;
    expect(target, findsOneWidget);
    await tester.tap(target);
    await tester.pumpAndSettle();
  }

  testWidgets('full shell at 1280x800 opens device details on demand', (
    tester,
  ) async {
    await pumpShell(tester, const Size(1280, 800));
    // Shell chrome is present and the desktop sidebar is the navigation.
    expect(find.byType(DesktopSidebar), findsOneWidget);

    await goToDevices(tester);

    expect(find.byKey(const Key('nodes-detail-pane')), findsNothing);
    expect(find.byType(Dialog), findsNothing);

    await tester.tap(find.byKey(const Key('node-row-peer-direct-001')));
    await tester.pumpAndSettle();
    expect(find.byType(Dialog), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('full shell at 1440x900 opens device details on demand', (
    tester,
  ) async {
    await pumpShell(tester, const Size(1440, 900));
    await goToDevices(tester);

    expect(find.byType(DesktopSidebar), findsOneWidget);
    expect(find.byKey(const Key('nodes-detail-pane')), findsNothing);
    expect(find.byType(Dialog), findsNothing);

    await tester.tap(find.byKey(const Key('node-row-peer-direct-001')));
    await tester.pumpAndSettle();
    expect(find.byType(Dialog), findsOneWidget);
    expect(tester.takeException(), isNull);
  });

  testWidgets('full shell at 900x1000 keeps Devices list + dialog', (
    tester,
  ) async {
    await pumpShell(tester, const Size(900, 1000));
    await goToDevices(tester);

    // Medium shell at 900 uses the list + detail dialog presentation.
    expect(find.byType(AppNavRail), findsOneWidget);
    expect(find.byType(DesktopSidebar), findsNothing);
    expect(find.byKey(const Key('nodes-detail-pane')), findsNothing);

    await tester.tap(find.byKey(const Key('node-row-peer-direct-001')));
    await tester.pumpAndSettle();
    expect(find.byType(Dialog), findsWidgets);
    expect(find.byKey(const Key('nodes-mobile-detail')), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('full shell at 1200x800 keeps Devices list + dialog', (
    tester,
  ) async {
    await pumpShell(tester, const Size(1200, 800));
    await goToDevices(tester);

    // The wide shell still keeps the first level quiet.
    expect(find.byType(DesktopSidebar), findsOneWidget);
    expect(find.byKey(const Key('nodes-detail-pane')), findsNothing);

    // Selecting a peer opens the detail dialog.
    await tester.tap(find.byKey(const Key('node-row-peer-direct-001')));
    await tester.pumpAndSettle();
    expect(find.byType(Dialog), findsWidgets);
    expect(find.byKey(const Key('nodes-detail-pane')), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('full shell at 700x1000 uses compact page, never an inspector', (
    tester,
  ) async {
    await pumpShell(tester, const Size(700, 1000));
    await goToDevices(tester);

    // Medium shell: labeled rail, no sidebar, no inspector. The page behaves
    // compact, so selecting a peer opens the full-screen detail.
    expect(find.byType(AppNavRail), findsOneWidget);
    expect(find.byType(DesktopSidebar), findsNothing);
    expect(find.byKey(const Key('nodes-detail-pane')), findsNothing);

    await tester.tap(find.byKey(const Key('node-row-peer-direct-001')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('nodes-mobile-detail')), findsOneWidget);
    expect(find.byType(Dialog), findsNothing);
    expect(tester.takeException(), isNull);
  });

  testWidgets('full shell at 390x844 opens full-screen device detail', (
    tester,
  ) async {
    await pumpShell(tester, const Size(390, 844));
    await goToDevices(tester);

    // Compact phone shell: bottom navigation, no rail, no sidebar, no pane.
    expect(find.byType(NavigationBar), findsOneWidget);
    expect(find.byType(AppNavRail), findsNothing);
    expect(find.byType(DesktopSidebar), findsNothing);
    expect(find.byKey(const Key('nodes-detail-pane')), findsNothing);

    await tester.tap(find.byKey(const Key('node-row-peer-direct-001')));
    await tester.pumpAndSettle();
    expect(find.byKey(const Key('nodes-mobile-detail')), findsOneWidget);
    expect(find.byType(Dialog), findsNothing);
    expect(tester.takeException(), isNull);
  });
}
