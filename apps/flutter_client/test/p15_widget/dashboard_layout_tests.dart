part of '../p15_widget_test.dart';

void _registerDashboardLayoutTests() {
  for (final dark in [false, true]) {
    for (final spec in const [
      (width: 1280.0, scale: 1.0, zh: false, sideBySide: true),
      (width: 390.0, scale: 1.0, zh: true, sideBySide: false),
      (width: 320.0, scale: 2.0, zh: false, sideBySide: false),
      (width: 1280.0, scale: 2.0, zh: true, sideBySide: false),
    ]) {
      testWidgets('Home layout ${spec.width} scale ${spec.scale} dark $dark', (
        tester,
      ) async {
        await tester.binding.setSurfaceSize(Size(spec.width, 1000));
        addTearDown(() => tester.binding.setSurfaceSize(null));
        final stores = await _smokeStores(tester);
        addTearDown(stores.dispose);
        var deviceVisits = 0;
        await tester.pumpWidget(
          _DesignSystemHost(
            dark: dark,
            child: Builder(
              builder: (context) => MediaQuery(
                data: MediaQuery.of(context)
                    .copyWith(textScaler: TextScaler.linear(spec.scale)),
                child: AppStringsScope(
                  strings: AppStrings.fromCode(spec.zh ? 'zh' : 'en'),
                  child: DashboardPage(
                    settingsStore: stores.settingsStore,
                    statusStore: stores.statusStore,
                    onOpenRooms: () {},
                    onOpenDevices: () => deviceVisits++,
                  ),
                ),
              ),
            ),
          ),
        );
        await tester.pumpAndSettle();
        expect(tester.takeException(), isNull);

        final devices = tester.getRect(
          find.byKey(const Key('home-devices-panel')),
        );
        final traffic = tester.getRect(
          find.byKey(const Key('home-traffic-panel')),
        );
        if (spec.sideBySide) {
          expect(devices.top, traffic.top);
          expect(devices.right, lessThan(traffic.left));
        } else {
          expect(devices.bottom, lessThan(traffic.top));
        }

        // The duplicate header room shortcut is removed; room navigation
        // remains in the shell while the device preview keeps its real action.
        expect(find.byKey(const Key('home-room-shortcut')), findsNothing);
        final allDevices = find.byKey(const Key('home-view-all-devices'));
        await tester.ensureVisible(allDevices);
        await tester.pumpAndSettle();
        await tester.tap(allDevices);
        expect(deviceVisits, 1);
        expect(tester.takeException(), isNull);
      });
    }
    testWidgets('sidebar keyboard focus and activation dark $dark', (
      tester,
    ) async {
      final stores = await _smokeStores(tester);
      addTearDown(stores.dispose);
      P2WlanSection? visited;
      await tester.pumpWidget(
        _DesignSystemHost(
          dark: dark,
          child: Align(
            alignment: Alignment.centerLeft,
            child: DesktopSidebar(
              selected: P2WlanSection.home,
              strings: AppStrings.fromCode('en'),
              statusStore: stores.statusStore,
              onSelect: (section) => visited = section,
              onFooterTap: () {},
            ),
          ),
        ),
      );
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.pumpAndSettle();
      final home = find.byKey(const ValueKey('sidebar-home'));
      final decoration =
          tester
                  .widget<AnimatedContainer>(
                    find
                        .descendant(
                          of: home,
                          matching: find.byType(AnimatedContainer),
                        )
                        .first,
                  )
                  .decoration!
              as BoxDecoration;
      final theme = dark ? AppTheme.darkTheme : AppTheme.lightTheme;
      expect(
        (decoration.border! as Border).top.color,
        theme.colorScheme.primary,
      );
      await tester.sendKeyEvent(LogicalKeyboardKey.tab);
      await tester.sendKeyEvent(LogicalKeyboardKey.enter);
      await tester.pumpAndSettle();
      expect(visited, P2WlanSection.devices);
      expect(tester.takeException(), isNull);
    });
  }
}
