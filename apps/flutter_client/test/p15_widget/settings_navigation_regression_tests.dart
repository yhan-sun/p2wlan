part of '../p15_widget_test.dart';

void _registerSettingsNavigationRegressionTests() {
  Future<void> onDesktop(Future<void> Function() body) async {
    debugDefaultTargetPlatformOverride = TargetPlatform.macOS;
    try {
      await body();
    } finally {
      debugDefaultTargetPlatformOverride = null;
    }
  }

  testWidgets(
    'Settings navigation keeps Back reachable after scrolling and preserves drafts',
    (tester) => onDesktop(() async {
      final stores = await _pumpSettingsShell(tester, const Size(900, 700));
      addTearDown(stores.dispose);
      await tester.tap(find.text('Advanced Network'));
      await tester.pumpAndSettle();
      await tester.enterText(_settingsTextField('MTU'), '1333');
      await tester.pumpAndSettle();

      final detail = find.byKey(
        const PageStorageKey('settings-advancedNetwork'),
      );
      final back = find.byTooltip('Back');
      expect(back.hitTestable(), findsOneWidget);
      await tester.drag(detail, const Offset(0, -1000));
      await tester.pumpAndSettle();
      final scrollable = tester.state<ScrollableState>(
        find.descendant(of: detail, matching: find.byType(Scrollable)).first,
      );
      expect(scrollable.position.pixels, greaterThan(0));
      expect(back.hitTestable(), findsOneWidget);

      await tester.tap(back);
      await tester.pumpAndSettle();
      expect(find.text('General'), findsOneWidget);
      expect(find.text('Discard unsaved changes?'), findsNothing);
      await tester.tap(find.text('Advanced Network'));
      await tester.pumpAndSettle();
      await tester.ensureVisible(_settingsTextField('MTU'));
      expect(
        tester.widget<TextField>(_settingsTextField('MTU')).controller!.text,
        '1333',
      );
      expect(find.text('Unsaved changes'), findsOneWidget);
      expect(tester.takeException(), isNull);
    }),
  );

  testWidgets(
    'Settings navigation aligns the description and keeps short large-text forms scrollable',
    (tester) => onDesktop(() async {
      final stores = await _pumpSettingsShell(
        tester,
        const Size(900, 900),
        textScale: 2,
      );
      addTearDown(stores.dispose);
      final category = find.text('Advanced Network');
      await tester.ensureVisible(category);
      await tester.pumpAndSettle();
      await tester.tap(category);
      await tester.pumpAndSettle();
      tester.view.physicalSize = const Size(900, 560);
      await tester.binding.setSurfaceSize(const Size(900, 560));
      await tester.pumpAndSettle();

      final description = find.text(
        AppStrings.fromCode('en').advancedNetworkSubtitle,
      );
      expect(
        tester.getTopLeft(description).dx,
        closeTo(tester.getTopLeft(find.text('Advanced Network')).dx, 0.1),
      );
      final detail = find.byKey(
        const PageStorageKey('settings-advancedNetwork'),
      );
      expect(tester.getSize(detail).height, greaterThan(100));
      await tester.drag(detail, const Offset(0, -1200));
      await tester.pumpAndSettle();
      expect(find.byTooltip('Back').hitTestable(), findsOneWidget);
      await tester.tap(find.byTooltip('Back'));
      await tester.pumpAndSettle();
      expect(
        find.byKey(const ValueKey('settings-category-card-general')),
        findsOneWidget,
      );
      expect(tester.takeException(), isNull);
    }),
  );

  testWidgets(
    'Settings navigation preserves detail and draft across resize and system Back',
    (tester) => onDesktop(() async {
      final stores = await _pumpSettingsShell(tester, const Size(900, 700));
      addTearDown(stores.dispose);
      await tester.tap(find.text('Advanced Network'));
      await tester.pumpAndSettle();
      await tester.enterText(_settingsTextField('MTU'), '1333');
      await tester.pumpAndSettle();

      tester.view.physicalSize = const Size(1280, 900);
      await tester.binding.setSurfaceSize(const Size(1280, 900));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('settings-category-rail')), findsOneWidget);
      expect(find.byTooltip('Back'), findsNothing);
      expect(
        tester.widget<TextField>(_settingsTextField('MTU')).controller!.text,
        '1333',
      );

      tester.view.physicalSize = const Size(900, 700);
      await tester.binding.setSurfaceSize(const Size(900, 700));
      await tester.pumpAndSettle();
      expect(find.byKey(const Key('settings-category-rail')), findsNothing);
      expect(find.byTooltip('Back').hitTestable(), findsOneWidget);
      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(find.text('General'), findsOneWidget);
      expect(find.text('Discard unsaved changes?'), findsNothing);

      await tester.binding.handlePopRoute();
      await tester.pumpAndSettle();
      expect(find.text('Discard unsaved changes?'), findsOneWidget);
      await tester.tap(find.text('Continue editing'));
      await tester.pumpAndSettle();
      await tester.tap(find.text('Advanced Network'));
      await tester.pumpAndSettle();
      expect(
        tester.widget<TextField>(_settingsTextField('MTU')).controller!.text,
        '1333',
      );
      expect(tester.takeException(), isNull);
    }),
  );
}
